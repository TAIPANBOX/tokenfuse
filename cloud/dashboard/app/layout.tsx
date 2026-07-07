import "./globals.css";

export const metadata = {
  title: "TokenFuse Cloud",
  description: "Enforce budgets and pull the Breaker across every TokenFuse gateway.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
