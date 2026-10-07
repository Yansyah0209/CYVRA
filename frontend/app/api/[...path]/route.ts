import { NextRequest, NextResponse } from "next/server";
const allowed =
  /^(projects(?:\/[a-zA-Z0-9-]+(?:\/(?:demo|import|dataset|analysis|simulate|recommendations|explain))?)?)$/;
async function proxy(
  req: NextRequest,
  context: { params: Promise<{ path: string[] }> },
) {
  const { path } = await context.params;
  const target = path.join("/");
  if (!allowed.test(target))
    return NextResponse.json({ detail: "Unknown route" }, { status: 404 });
  try {
    const body = req.method === "POST" ? await req.text() : undefined;
    if (body && Buffer.byteLength(body) > 2_000_000)
      return NextResponse.json(
        { detail: "Request exceeds 2 MB" },
        { status: 413 },
      );
    const response = await fetch(
      `${process.env.BACKEND_URL || "http://127.0.0.1:8000"}/api/${target}`,
      {
        method: req.method,
        body,
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": process.env.CYVRA_API_KEY || "",
        },
        cache: "no-store",
        signal: AbortSignal.timeout(60000),
      },
    );
    return new NextResponse(await response.text(), {
      status: response.status,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
      },
    });
  } catch {
    return NextResponse.json(
      { detail: "Backend unavailable. Start the API and check BACKEND_URL." },
      { status: 502 },
    );
  }
}
export const GET = proxy;
export const POST = proxy;
