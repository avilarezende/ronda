import type { Metadata } from "next";
import { Public_Sans, Source_Serif_4 } from "next/font/google";
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import "./globals.css";

const sans = Public_Sans({
  subsets: ["latin"],
  variable: "--font-public",
});

const serif = Source_Serif_4({
  subsets: ["latin"],
  variable: "--font-source-serif",
});

export const metadata: Metadata = {
  title: "Ronda · Plantão de vulnerabilidades",
  description:
    "Bancada diária para acompanhar o catálogo CISA KEV, publicações recentes da NVD e novidades do CERT.br.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="pt-BR" className={`${sans.variable} ${serif.variable} h-full antialiased`}>
      <body className={`${sans.className} min-h-full`}>
        <TooltipProvider>
          {children}
          <Toaster position="top-right" />
        </TooltipProvider>
      </body>
    </html>
  );
}
