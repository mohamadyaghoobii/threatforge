import "./globals.css";
import type { Metadata } from "next";
import Sidebar from "../components/Sidebar";
import Topbar from "../components/Topbar";

export const metadata: Metadata = {
  title: "MetaSec Security Center",
  description: "MetaSec Security Center — detection engineering, MITRE ATT&CK coverage, multi-SIEM query generation, and threat intelligence.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="shell">
          <Sidebar />
          <div className="content">
            <Topbar />
            <main className="main">{children}</main>
          </div>
        </div>
      </body>
    </html>
  );
}
