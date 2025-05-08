'use client';

import { useEffect, useState } from 'react';

interface Log {
  id: number;
  userId: number | null;
  action: string;
  detail: string;
  createdAt: string;
}

export default function Home() {
  const [logs, setLogs] = useState<Log[]>([]);

  useEffect(() => {
    fetch('/api/logs')
      .then((res) => res.json())
      .then((data) => setLogs(data));
  }, []);

  return (
    <div className="space-y-8">
      <h2 className="text-2xl font-semibold text-black">🏠 Home</h2>

      <section className="bg-[#1E1E2F] border border-[#2E2E42] rounded-xl p-6 shadow-md max-w-5xl mx-auto">
        <div className="mb-4">
          <h3 className="text-lg font-semibold text-white">
            🦠 이번 달 랜섬웨어 침입 시도: {logs.length}건
          </h3>
        </div>

        {/* 로그 표 */}
        <div className="overflow-x-auto mt-6">
          <table className="min-w-full text-sm text-white">
            <thead>
              <tr className="bg-[#2A2A3C] text-left">
                <th className="p-3">날짜</th>
                <th className="p-3">유저 ID</th>
                <th className="p-3">행동</th>
                <th className="p-3">설명</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => (
                <tr
                  key={log.id}
                  className="border-b border-[#3B3B50] hover:bg-[#2a2a2a]"
                >
                  <td className="p-3">
                    {new Date(log.createdAt).toLocaleString()}
                  </td>
                  <td className="p-3">{log.userId ?? '-'}</td>
                  <td className="p-3">
                    <span className="bg-red-600 text-white px-2 py-1 rounded text-xs">
                      {log.action}
                    </span>
                  </td>
                  <td className="p-3">{log.detail}</td>
                </tr>
              ))}
              {logs.length === 0 && (
                <tr>
                  <td colSpan={4} className="text-center p-4 text-gray-400">
                    📭 이번 달 탐지된 랜섬웨어 침입이 없습니다.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
