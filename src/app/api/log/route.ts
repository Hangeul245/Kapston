// 기존 API 예시 수정
import { NextResponse } from 'next/server';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export async function GET() {
  const startOfMonth = new Date(
    new Date().getFullYear(),
    new Date().getMonth(),
    1
  );
  const now = new Date();

  const logs = await prisma.log.findMany({
    where: {
      action: 'RANSOMWARE_ATTACK',
      createdAt: {
        gte: startOfMonth,
        lte: now,
      },
    },
    orderBy: {
      createdAt: 'desc',
    },
  });

  return NextResponse.json(logs);
}
