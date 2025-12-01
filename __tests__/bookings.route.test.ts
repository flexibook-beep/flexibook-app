import { GET, POST } from '@/app/api/bookings/route';
import { NextResponse } from 'next/server';

// Mocks
jest.mock('next-auth', () => ({
  getServerSession: jest.fn(),
}));

jest.mock('@/lib/prisma', () => ({
  prisma: {
    booking: {
      findMany: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
    },
    teacher: { findUnique: jest.fn() },
    user: { findUnique: jest.fn() },
    payment: { create: jest.fn() },
    notification: { create: jest.fn() },
  },
}));

jest.mock('@/lib/validations', () => ({
  bookingSchema: { parse: (x: any) => x },
}));

jest.mock('@/lib/time-utils', () => ({
  checkAvailability: jest.fn(() => true),
}));

jest.mock('@/lib/meeting-links', () => ({
  generateMeetingLink: jest.fn(async () => 'https://meet.example/abc'),
}));

import { getServerSession } from 'next-auth';
import { prisma } from '@/lib/prisma';
import { checkAvailability } from '@/lib/time-utils';
import { generateMeetingLink } from '@/lib/meeting-links';

const asReq = (url: string, body?: any) => {
  const anyReq: any = { url };
  if (body !== undefined) {
    anyReq.json = jest.fn().mockResolvedValue(body);
  }
  return anyReq as any;
};

beforeEach(() => {
  jest.clearAllMocks();
});

describe('GET /api/bookings', () => {
  it('returns 401 when unauthorized', async () => {
    (getServerSession as jest.Mock).mockResolvedValue(null);

    const res = await GET(asReq('http://test.local/api/bookings'));
    expect(res.status).toBe(401);
    const data = await (res as NextResponse).json();
    expect(data).toHaveProperty('error', 'Unauthorized');
  });

  it('returns bookings for authenticated student', async () => {
    (getServerSession as jest.Mock).mockResolvedValue({
      user: { id: 'stu1', role: 'STUDENT', name: 'Stu', email: 's@example.com' },
    });

    const bookings = [
      {
        id: 'b1',
        studentId: 'stu1',
        teacherId: 't1',
        startTime: new Date(),
        endTime: new Date(Date.now() + 3600000),
        durationMinutes: 60,
        notes: null,
        studentTimezone: 'UTC',
        teacherTimezone: 'UTC',
        status: 'CONFIRMED',
        meetingLink: null,
        student: { id: 'stu1', name: 'Stu', email: 's@example.com', image: null },
        teacher: { id: 't1', name: 'Teach', email: 't@example.com', image: null },
        payment: null,
      },
    ];

    (prisma.booking.findMany as jest.Mock).mockResolvedValue(bookings);

    const res = await GET(
      asReq('http://test.local/api/bookings?status=CONFIRMED')
    );

    expect(res.status).toBe(200);
    const data = await (res as NextResponse).json();
    expect(data).toHaveProperty('bookings');
    expect(Array.isArray(data.bookings)).toBe(true);
    expect(data.bookings).toHaveLength(1);
  });
});

describe('POST /api/bookings', () => {
  it('returns 401 when unauthorized', async () => {
    (getServerSession as jest.Mock).mockResolvedValue(null);
    const res = await POST(asReq('http://test.local/api/bookings', {}));
    expect(res.status).toBe(401);
    const data = await (res as NextResponse).json();
    expect(data).toHaveProperty('error', 'Unauthorized');
  });

  it('creates a booking when valid', async () => {
    (getServerSession as jest.Mock).mockResolvedValue({
      user: {
        id: 'stu1',
        role: 'STUDENT',
        name: 'Student',
        email: 'student@example.com',
      },
    });

    const start = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000); // +2 days
    const body = {
      teacherId: 't1',
      startTime: start.toISOString(),
      durationMinutes: 60,
      notes: 'Hello',
    };

    (prisma.teacher.findUnique as jest.Mock).mockResolvedValue({
      userId: 't1',
      hourlyRate: 120,
      bufferTime: 0,
      user: { name: 'Teacher', email: 't@example.com', timezone: 'UTC' },
    });

    (prisma.booking.findMany as jest.Mock).mockResolvedValue([]);
    (prisma.user.findUnique as jest.Mock).mockResolvedValue({
      id: 'stu1',
      timezone: 'UTC',
    });

    const createdBooking = {
      id: 'b1',
      studentId: 'stu1',
      teacherId: 't1',
      startTime: start,
      endTime: new Date(start.getTime() + 60 * 60000),
      durationMinutes: 60,
      notes: 'Hello',
      studentTimezone: 'UTC',
      teacherTimezone: 'UTC',
      status: 'CONFIRMED',
      meetingLink: null,
      student: { id: 'stu1', name: 'Student', email: 'student@example.com', image: null },
      teacher: { id: 't1', name: 'Teacher', email: 't@example.com', image: null },
    };

    (prisma.booking.create as jest.Mock).mockResolvedValue(createdBooking);

    const res = await POST(asReq('http://test.local/api/bookings', body));

    expect(checkAvailability).toHaveBeenCalled();
    expect(prisma.booking.create).toHaveBeenCalled();
    expect(prisma.payment.create).toHaveBeenCalled();
    expect(generateMeetingLink).toHaveBeenCalled();
    expect(prisma.booking.update).toHaveBeenCalledWith({
      where: { id: 'b1' },
      data: { meetingLink: 'https://meet.example/abc' },
    });
    // one confirmation + up to two reminders
    expect((prisma.notification.create as jest.Mock).mock.calls.length).toBeGreaterThanOrEqual(1);

    expect(res.status).toBe(201);
    const data = await (res as NextResponse).json();
    expect(data).toHaveProperty('booking');
    expect(data.booking).toHaveProperty('id', 'b1');
    expect(data.booking).toHaveProperty('meetingLink', 'https://meet.example/abc');
    expect(data).toHaveProperty('message');
  });
});
