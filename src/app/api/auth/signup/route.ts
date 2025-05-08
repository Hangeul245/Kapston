import { NextResponse } from 'next/server';
import bcrypt from 'bcrypt';
import { prisma } from '@/lib/prisma';

// 비밀번호 유효성 검사
function isValidPassword(password: string) {
  const hasMinLength = password.length >= 8;
  const hasLetters = /[a-zA-Z]/.test(password);
  const hasNumbers = /[0-9]/.test(password);
  const hasSpecials = /[^a-zA-Z0-9]/.test(password);
  return hasMinLength && hasLetters && hasNumbers && hasSpecials;
}

// POST 요청 처리
export async function POST(req: Request) {
  try {
    const { email, password, name } = await req.json();

    if (!email || !password || !name) {
      return NextResponse.json(
        { error: '모든 항목을 입력해야 합니다.' },
        { status: 400 }
      );
    }

    if (!isValidPassword(password)) {
      return NextResponse.json(
        { error: '비밀번호는 8자 이상, 영어+숫자+특수문자 포함해야 합니다.' },
        { status: 400 }
      );
    }

    // cloud 테이블에서 ip(email 저장한 곳)으로 기존 사용자 찾기
    const existingUser = await prisma.cloud.findFirst({
      where: {
        ip: email,
      },
    });

    if (existingUser) {
      return NextResponse.json(
        { error: '이미 등록된 이메일입니다.' },
        { status: 400 }
      );
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // cloud 테이블에 회원가입 정보 저장
    await prisma.cloud.create({
      data: {
        ip: email, // 이메일을 ip 칼럼에
        message: hashedPassword, // 비밀번호(hash)를 message 칼럼에
        filename: name, // 이름을 filename 칼럼에
        log_time: new Date(), // 가입 시간 저장
        data: null, // 필요 없으면 null
      },
    });

    return NextResponse.json({ message: '회원가입 성공' });
  } catch (error) {
    console.error('회원가입 에러:', error);
    return NextResponse.json({ error: '서버 내부 오류' }, { status: 500 });
  }
}
