"""Bounded public HTTP fetch with pinned DNS and normal TLS verification."""

import http.client
import ipaddress
import socket
import ssl
import time
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit, urljoin, quote

MAX_BODY = 512 * 1024
TIMEOUT = 8
DNS_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="cyvra-dns")
DNS_SLOTS = threading.BoundedSemaphore(2)


class TargetError(ValueError):
    pass


@dataclass(frozen=True)
class Target:
    url: str
    scheme: str
    host: str
    port: int
    path: str


def normalize_url(value: str) -> Target:
    if any(ord(c) < 33 or ord(c) == 127 for c in value) or "\\" in value:
        raise TargetError("URL contains whitespace or invalid characters")
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise TargetError("Enter a full http:// or https:// URL")
        if parsed.username is not None or parsed.password is not None:
            raise TargetError("URLs containing credentials are not supported")
        host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        if not host or len(host) > 253 or "%" in host:
            raise TargetError("Invalid host")
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        if port != (443 if parsed.scheme == "https" else 80):
            raise TargetError("Only standard HTTP and HTTPS ports are supported")
        netloc = "[" + host + "]" if ":" in host else host
        path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
        # Strip query and fragment: avoid sending or retaining accidental tokens.
        url = urlunsplit((parsed.scheme, netloc, path, "", ""))
        return Target(url, parsed.scheme, host, port, path)
    except (UnicodeError, ValueError) as error:
        if isinstance(error, TargetError):
            raise
        raise TargetError("Invalid URL") from error


def public_addresses(target: Target, timeout: float = TIMEOUT) -> list[str]:
    try:
        if not DNS_SLOTS.acquire(blocking=False):
            raise TargetError("DNS resolver is busy; retry shortly")
        future = DNS_POOL.submit(socket.getaddrinfo, target.host, target.port, 0, socket.SOCK_STREAM)
        future.add_done_callback(lambda _: DNS_SLOTS.release())
        try:
            records = future.result(timeout=timeout)
        except FutureTimeout as error:
            raise TargetError("Domain resolution timed out") from error
    except socket.gaierror as error:
        raise TargetError("Domain could not be resolved") from error
    addresses = sorted({r[4][0] for r in records})
    if not addresses:
        raise TargetError("Domain has no usable addresses")
    for value in addresses:
        ip = ipaddress.ip_address(value)
        mapped = getattr(ip, "ipv4_mapped", None)
        if not ip.is_global or ip.is_multicast or (mapped and not mapped.is_global):
            raise TargetError("Only public internet addresses are supported; local/private targets are blocked")
        if isinstance(ip, ipaddress.IPv6Address) and (ip.sixtofour or ip.teredo):
            raise TargetError("IPv6 transition addresses are not supported")
    return addresses


class PinnedConnection(http.client.HTTPConnection):
    def __init__(self, target: Target, address: str, timeout: float):
        super().__init__(target.host, target.port, timeout=timeout)
        self.target = target
        self.address = address

    def connect(self):
        # Numeric validated address, not a second hostname lookup. Keep the original
        # hostname for certificate verification and SNI, and for the Host header.
        family = socket.AF_INET6 if ":" in self.address else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            self.sock = sock
            sock.settimeout(self.timeout)
            sock.connect((self.address, self.target.port))
            if self.target.scheme == "https":
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=self.target.host)
            self.sock = sock
        except BaseException:
            sock.close()
            raise


@dataclass
class Page:
    url: str
    status: int
    headers: list[tuple[str, str]]
    body: bytes
    truncated: bool
    redirects: list[dict]
    notes: list[str]


def fetch_page(value: str) -> Page:
    initial = normalize_url(value)
    target = initial
    started = time.monotonic()
    redirects = []
    for hop in range(4):
        remaining = 25 - (time.monotonic() - started)
        if remaining <= 0:
            raise TargetError("Assessment timed out")
        addresses = public_addresses(target, min(TIMEOUT, remaining))
        remaining = 25 - (time.monotonic() - started)
        if remaining <= 0:
            raise TargetError("Assessment timed out")
        connection = PinnedConnection(target, addresses[0], min(TIMEOUT, remaining))

        def abort():
            if connection.sock:
                try:
                    connection.sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        watchdog = threading.Timer(remaining, abort)
        watchdog.daemon = True
        watchdog.start()
        try:
            connection.request(
                "GET",
                target.path,
                headers={
                    "Host": "[" + target.host + "]" if ":" in target.host else target.host,
                    "User-Agent": "CYVRA/0.2 (authorized security posture check)",
                    "Accept": "text/html,application/json;q=0.8,*/*;q=0.1",
                    "Accept-Encoding": "identity",
                },
            )
            response = connection.getresponse()
            headers = response.getheaders()
            if sum(len(k) + len(v) for k, v in headers) > 65536:
                raise TargetError("Response headers exceeded the assessment limit")
            location = response.getheader("Location")
            notes = []
            if response.status in (301, 302, 303, 307, 308) and location:
                next_target = normalize_url(urljoin(target.url, location))
                if (
                    next_target.host == initial.host
                    and not (target.scheme == "https" and next_target.scheme == "http")
                    and hop < 3
                ):
                    # Redirect destinations are re-resolved and pinned on the next iteration.
                    redirects.append(
                        {"from": target.url, "to": next_target.url, "status": response.status, "followed": True}
                    )
                    target = next_target
                    continue
                redirects.append(
                    {"from": target.url, "to": next_target.url, "status": response.status, "followed": False}
                )
                notes.append(
                    "Redirect was not followed: cross-host, HTTPS downgrade, or redirect limit. Inspect the destination separately."
                )
            body = bytearray()
            while len(body) <= MAX_BODY:
                remaining = 25 - (time.monotonic() - started)
                if remaining <= 0:
                    raise TargetError("Assessment timed out")
                if connection.sock:
                    connection.sock.settimeout(min(TIMEOUT, remaining))
                chunk = response.read1(min(65536, MAX_BODY + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
            return Page(
                target.url, response.status, headers, bytes(body[:MAX_BODY]), len(body) > MAX_BODY, redirects, notes
            )
        except ssl.SSLCertVerificationError as error:
            raise TargetError(
                "TLS certificate verification failed. No page assessment completed; review the certificate and trust chain."
            ) from error
        except (OSError, http.client.HTTPException) as error:
            raise TargetError(
                "Could not retrieve the page securely. Check accessibility, TLS configuration, and network access."
            ) from error
        finally:
            watchdog.cancel()
            connection.close()
    raise TargetError("Redirect limit reached")
