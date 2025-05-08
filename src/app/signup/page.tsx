'use client';

import { useState } from 'react';

export default function SignupPage() {
  const [name, setName] = useState('');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [passwordCheck, setPasswordCheck] = useState('');
  const [message, setMessage] = useState('');

  const validatePassword = (password: string, email: string) => {
    const hasMinLength = password.length >= 8;
    const hasLetters = /[a-zA-Z]/.test(password);
    const hasNumbers = /[0-9]/.test(password);
    const hasSpecials = /[^a-zA-Z0-9]/.test(password);
    const notSameAsEmail = password !== email;

    return (
      hasMinLength && hasLetters && hasNumbers && hasSpecials && notSameAsEmail
    );
  };

  // 닉네임 중복확인 (임시)
  const checkNameDuplicate = () => {
    alert('닉네임 중복확인(임시)');
  };

  // 아이디 중복확인 (임시)
  const checkUsernameDuplicate = () => {
    alert('아이디 중복확인(임시)');
  };

  // 이메일 인증 (임시)
  const verifyEmail = () => {
    alert('이메일 인증확인(임시)');
  };

  const handleSignup = async () => {
    if (password !== passwordCheck) {
      setMessage('비밀번호가 일치하지 않습니다.');
      return;
    }

    if (!validatePassword(password, email)) {
      setMessage(
        '비밀번호는 영어, 숫자, 특수문자를 포함한 8자 이상이며, 아이디(이메일)와 같을 수 없습니다.'
      );
      return;
    }

    const res = await fetch('/api/auth/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, username, password, name }),
    });

    const data = await res.json();
    if (res.ok) {
      setMessage('회원가입 성공!');
    } else {
      setMessage(data.error || '회원가입 실패');
    }
  };

  return (
    <div className="p-8 max-w-md mx-auto">
      <h2 className="text-2xl font-bold mb-6">회원가입</h2>

      {/* 닉네임 입력 + 중복확인 버튼 */}
      <div className="flex gap-2 mb-2">
        <input
          placeholder="닉네임"
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="border p-2 flex-1 rounded"
        />
        <button
          onClick={checkNameDuplicate}
          className="bg-gray-700 text-white px-3 rounded"
        >
          중복확인
        </button>
      </div>

      {/* 아이디 입력 + 중복확인 버튼 */}
      <div className="flex gap-2 mb-2">
        <input
          placeholder="아이디"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          className="border p-2 flex-1 rounded"
        />
        <button
          onClick={checkUsernameDuplicate}
          className="bg-gray-700 text-white px-3 rounded"
        >
          중복확인
        </button>
      </div>

      {/* 이메일 입력 + 인증 버튼 */}
      <div className="flex gap-2 mb-2">
        <input
          placeholder="이메일"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="border p-2 flex-1 rounded"
        />
        <button
          onClick={verifyEmail}
          className="bg-gray-700 text-white px-3 rounded"
        >
          인증
        </button>
      </div>

      {/* 비밀번호 입력 */}
      <input
        type="password"
        placeholder="비밀번호"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        className="border p-2 w-full mb-2 rounded"
      />

      {/* 비밀번호 확인 입력 */}
      <input
        type="password"
        placeholder="비밀번호 확인"
        value={passwordCheck}
        onChange={(e) => setPasswordCheck(e.target.value)}
        className="border p-2 w-full mb-4 rounded"
      />

      {/* 가입하기 버튼 */}
      <button
        onClick={handleSignup}
        className="bg-blue-500 hover:bg-blue-600 text-white py-2 px-4 rounded w-full"
      >
        가입하기
      </button>

      {/* 메시지 표시 */}
      {message && <p className="mt-4 text-red-500">{message}</p>}
    </div>
  );
}
