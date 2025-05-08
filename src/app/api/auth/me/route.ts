import { cookies } from 'next/headers';
import { NextResponse } from 'next/server';

export async function GET() {
  const session = (await cookies()).get('session')?.value;
  if (!session) return NextResponse.json({ authenticated: false });

  return NextResponse.json({ authenticated: true, user: JSON.parse(session) });
}
