'use client';

import { useEffect, useState } from 'react';

interface Log {
  id: number;
  userId: number | null;
  action: string;
  detail: string;
  createdAt: string;
}

export default function LogBoardPage() {
  const [logs, setLogs] = useState<Log[]>([]);

  useEffect(() => {
    fetch('/api/logs')
      .then(res => res.json())
      .then(data => setLogs(data));
  }, []);

  return (
    <div className="p-10">
      <h2 className="text-2xl font-bold mb-6 text-white">로그 기록</h2>
      <div className="overflow-x-auto">
        <table className="min-w-full text-sm text-white">
          <thead>
            <tr className="bg-[#2A2A3C] text-left">
              <th className="p-3">ID</th>
              <th className="p-3">User ID</th>
              <th className="p-3">Action</th>
              <th className="p-3">Detail</th>
              <th className="p-3">Created At</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((log) => (
              <tr key={log.id} className="border-b border-[#3B3B50] hover:bg-[#2a2a2a]">
                <td className="p-3">{log.id}</td>
                <td className="p-3">{log.userId ?? '-'}</td>
                <td className="p-3">{log.action}</td>
                <td className="p-3">{log.detail}</td>
                <td className="p-3">{new Date(log.createdAt).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
