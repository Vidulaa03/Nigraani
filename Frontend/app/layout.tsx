import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "NIGRAANI | Cybersecurity Intelligence Platform",
  description: "AI-assisted API threat detection and risk intelligence platform",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-[#f7f5ef] text-[#27251f] antialiased">
        {children}
      </body>
    </html>
  );
}
