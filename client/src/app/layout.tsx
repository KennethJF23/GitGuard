import type { Metadata } from "next";
import { Inter, Geist, Black_Ops_One } from "next/font/google";
import "./globals.css";
import { cn } from "@/lib/utils";
import AuthGate from "@/components/auth/AuthGate";
import LenisProvider from "@/components/providers/LenisProvider";

const geist = Geist({subsets:['latin'],variable:'--font-sans'});

const blackOpsOne = Black_Ops_One({
  weight: '400',
  subsets: ['latin'],
  variable: '--font-black-ops-one',
});

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
});

export const metadata: Metadata = {
  title: "GitGuard | GitHub Repository Malware Risk Scanner",
  description: "Analyze GitHub repositories with keyword intelligence, ZIP source scanning, deterministic malware verdicts, and JWT-secured access.",
  keywords: ["gitguard", "github security", "repository scanner", "malware detection", "jwt auth", "redis cache"],
  openGraph: {
    title: "GitGuard | GitHub Repository Malware Risk Scanner",
    description: "Analyze GitHub repositories with keyword intelligence, ZIP source scanning, deterministic malware verdicts, and JWT-secured access.",
    type: "website",
    locale: "en_GB",
    url: "https://gitguard.local",
    siteName: "GitGuard",
  },
  twitter: {
    card: "summary_large_image",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={cn("h-full", "antialiased", inter.variable, "font-sans", geist.variable, blackOpsOne.variable)}
    >
      <body className="min-h-full flex flex-col overflow-x-hidden">
        <LenisProvider>
          <AuthGate>{children}</AuthGate>
        </LenisProvider>
      </body>
    </html>
  );
}
