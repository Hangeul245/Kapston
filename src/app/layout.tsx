import Link from 'next/link';
import './globals.css';
import { LanguageProvider } from './context/LanguageContext';

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="ko">
      <body className="antialiased bg-white text-[#1E2A38]">
        <LanguageProvider>
          <div className="flex h-screen">
            {/* Sidebar */}
            <aside className="w-72 bg-[#F5F7FA] border-r border-[#E0E6ED] p-6 flex flex-col rounded-r-3xl shadow-md text-[#1E2A38]">
              <h1 className="text-2xl font-bold mb-10 tracking-tight">
                흰둥단
              </h1>
              <nav className="flex flex-col gap-4 text-sm">
                {[
                  { href: '/', label: '홈' },
                  { href: '/dashboard', label: '대시보드' },
                  { href: '/textlogbox', label: '텍스트보드방식' },
                  { href: '/settings', label: '설정' },
                ].map(({ href, label }) => (
                  <Link
                    key={href}
                    href={href}
                    className="px-3 py-2 rounded-lg hover:bg-[#E0E6ED] transition text-[#1E2A38]"
                  >
                    {label}
                  </Link>
                ))}
              </nav>
            </aside>

            {/* Main Content */}
            <main className="flex-1 overflow-y-auto p-10 bg-white relative text-[#1E2A38]">
              {/* 우측 상단 고정 버튼 */}
              <div className="absolute top-4 right-10 flex items-center gap-4">
                {/* 무조건 로그인 버튼만 */}
                <Link
                  href="/login"
                  className="px-4 py-2 bg-[#2ECC71] hover:bg-[#28b765] text-white font-semibold rounded-lg transition"
                >
                  로그인
                </Link>
              </div>

              {children}
            </main>
          </div>
        </LanguageProvider>
      </body>
    </html>
  );
}
