'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link'; // ✅ 추가

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  async function handleLogin(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json();

      if (res.ok) {
        router.push('/dashboard'); // 성공하면 dashboard로 이동
      } else {
        setError(data.error || '로그인 실패');
      }
    } catch (err) {
      console.error('로그인 요청 에러:', err);
      setError('서버 통신 오류가 발생했습니다.');
    }
  }

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-100 p-6">
      <h1 className="text-3xl font-bold mb-8">로그인</h1>

      <form
        onSubmit={handleLogin}
        className="flex flex-col gap-6 w-full max-w-md"
      >
        <input
          type="email"
          placeholder="이메일"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          className="border p-3 rounded text-gray-800"
        />
        <input
          type="password"
          placeholder="비밀번호"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          className="border p-3 rounded text-gray-800"
        />
        {error && <p className="text-red-500 text-sm">{error}</p>}

        <button
          type="submit"
          className="bg-blue-500 hover:bg-blue-600 text-white py-3 font-bold rounded transition"
        >
          로그인
        </button>
      </form>

      {/* ✅ 로그인 밑에 회원가입 버튼 추가 */}
      <div className="mt-6 text-center">
        <p className="text-gray-600 mb-2">아직 계정이 없으신가요?</p>
        <Link
          href="/signup" // ✅ 회원가입 페이지 경로
          className="inline-block bg-green-500 hover:bg-green-600 text-white font-bold py-2 px-4 rounded transition"
        >
          회원가입 하기
        </Link>
      </div>
    </div>
  );
}
