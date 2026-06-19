import type { Metadata } from 'next';
import './globals.css';
import { ThemeProvider, THEME_BOOTSTRAP } from '../lib/theme';

export const metadata: Metadata = {
  title: 'Rasputin',
  description: 'Rasputin control plane',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    // suppressHydrationWarning: the bootstrap script mutates data-theme on the
    // client before React hydrates, which is an intentional server/client diff.
    <html lang="en" suppressHydrationWarning>
      <head>
        {/* Apply the saved theme before first paint — no flash of default. */}
        <script dangerouslySetInnerHTML={{ __html: THEME_BOOTSTRAP }} />
      </head>
      <body>
        <ThemeProvider>{children}</ThemeProvider>
      </body>
    </html>
  );
}
