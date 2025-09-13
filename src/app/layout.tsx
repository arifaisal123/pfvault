import './globals.css'; // 👈 This is crucial

export const metadata = { title: "Personal Finance Vault", description: "Encrypted personal finance dashboard" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
