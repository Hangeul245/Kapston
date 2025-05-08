'use client';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';

export default function DashboardPage() {
  const [user, setUser] = useState(null);
  const router = useRouter();

  useEffect(() => {
    fetch('/api/auth/me')
      .then((res) => res.json())
      .then((data) => {
        if (!data.authenticated) {
          router.push('/login');
        } else {
          setUser(data.user);
        }
      });
  }, []);

  if (!user) return <div>로딩 중...</div>;

  return (
    <div className="p-10">
      <h1 className="text-2xl font-bold mb-4">환영합니다, {user}님!</h1>
    </div>
  );
}
