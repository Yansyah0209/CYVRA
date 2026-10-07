import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = {
  title: "CYVRA — Cyber Risk Intelligence",
  description: "Evidence-aware defensive cyber risk analysis",
};
export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
