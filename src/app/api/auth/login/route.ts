import { NextResponse } from 'next/server';
import bcrypt from 'bcrypt';
import { prisma } from '@/lib/prisma'; // 네가 쓰는 prisma 인스턴스

export async function POST(req: Request) {
  try {
    const { email, password } = await req.json();

    if (!email || !password) {
      return NextResponse.json(
        { error: '이메일과 비밀번호를 모두 입력하세요.' },
        { status: 400 }
      );
    }

    // 1. 이메일로 DB 조회
    const user = await prisma.cloud.findFirst({
      where: {
        ip: email, // cloud 테이블의 ip에 이메일 저장되어 있음
      },
    });

    if (!user) {
      return NextResponse.json(
        { error: '등록되지 않은 이메일입니다.' },
        { status: 400 }
      );
    }

    // 2. 비밀번호 검증
    const isPasswordValid = await bcrypt.compare(password, user.message ?? '');

    if (!isPasswordValid) {
      return NextResponse.json(
        { error: '비밀번호가 일치하지 않습니다.' },
        { status: 400 }
      );
    }

    // 3. 닉네임 가져오기
    const nickname = user.filename ?? '사용자'; // filename 컬럼에 닉네임이 저장되어 있다고 가정

    // 4. 쿠키에 닉네임 저장
    const response = NextResponse.json({
      message: '로그인 성공',
    });

    response.cookies.set('nickname', nickname, {
      path: '/',
      httpOnly: false, // 클라이언트 측에서 읽을 수 있어야 하니까 false
      sameSite: 'lax',
    });

    return response;
  } catch (error) {
    console.error('로그인 에러:', error);
    return NextResponse.json(
      { error: '서버 내부 오류가 발생했습니다.' },
      { status: 500 }
    );
  }
}
