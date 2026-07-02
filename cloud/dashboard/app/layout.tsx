import "./globals.css";

export const metadata = {
  title: "TokenFuse Cloud",
  description: "Single pane of glass across your TokenFuse gateways",
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
