import type { Metadata } from "next";
import "./styles.css";

export const metadata: Metadata = {
  title: "NetAudit Engine",
  description: "Explainable multi-vendor network security compliance",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
