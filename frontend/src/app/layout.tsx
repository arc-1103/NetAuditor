import type { Metadata } from "next";
import "./styles.css";

export const metadata: Metadata = {
  title: "NetAudit Engine",
  description: "Explainable multi-vendor network security compliance",
};

// Sets data-theme on <html> before paint so there's no flash of the wrong
// theme while React hydrates; suppressHydrationWarning below tells React not
// to complain that this script changed an attribute it doesn't control.
const themeInitScript = `(function(){try{var t=localStorage.getItem("na_theme");if(t!=="light"&&t!=="dark"){t=window.matchMedia("(prefers-color-scheme: light)").matches?"light":"dark";}document.documentElement.setAttribute("data-theme",t);}catch(e){}})();`;

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeInitScript }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
