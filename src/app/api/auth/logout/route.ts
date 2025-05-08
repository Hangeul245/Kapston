import { NextResponse } from 'next/server';

export async function POST() {
  const response = NextResponse.redirect(
    new URL('/login', process.env.NEXT_PUBLIC_BASE_URL)
  );

  // nickname 쿠키 삭제
  response.cookies.set('nickname', '', {
    path: '/',
    maxAge: 0,
  });

  return response;
}
