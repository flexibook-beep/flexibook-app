import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { prisma } from "@/lib/prisma";
import { bookingSchema } from "@/lib/validations";
import { checkAvailability } from "@/lib/time-utils";
import { addMinutes } from "date-fns";
import { generateMeetingLink } from "@/lib/meeting-links";

export async function GET(req: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const searchParams = req.nextUrl.searchParams;
    const status = searchParams.get("status");
    const teacherId = searchParams.get("teacherId");

    const where: any = {};

    if (session.user.role === "STUDENT") {
      where.studentId = session.user.id;
    } else if (session.user.role === "TEACHER") {
      where.teacherId = session.user.id;
    }

    if (status) {
      where.status = status;
    }

    if (teacherId) {
      where.teacherId = teacherId;
    }

    const bookings = await prisma.booking.findMany({
      where,
      include: {
        student: {
          select: {
            id: true,
            name: true,
            email: true,
            image: true,
          },
        },
        teacher: {
          select: {
            id: true,
            name: true,
            email: true,
            image: true,
          },
        },
        payment: true,
      },
      orderBy: {
        startTime: "desc",
      },
    });

    return NextResponse.json({ bookings });
  } catch (error) {
    console.error("Error fetching bookings:", error);
    return NextResponse.json(
      { error: "Failed to fetch bookings" },
      { status: 500 }
    );
  }
}

export async function POST(req: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const body = await req.json();
    const validatedData = bookingSchema.parse(body);

    // Get teacher info
    const teacher = await prisma.teacher.findUnique({
      where: { userId: validatedData.teacherId },
      include: { user: true },
    });

    if (!teacher) {
      return NextResponse.json({ error: "Teacher not found" }, { status: 404 });
    }

    const startTime = new Date(validatedData.startTime);
    const endTime = addMinutes(startTime, validatedData.durationMinutes);

    // Check for existing bookings at this time
    const existingBookings = await prisma.booking.findMany({
      where: {
        teacherId: validatedData.teacherId,
        status: {
          in: ["PENDING_PAYMENT", "CONFIRMED"],
        },
        OR: [
          {
            startTime: {
              lte: endTime,
            },
            endTime: {
              gte: startTime,
            },
          },
        ],
      },
    });

    const hasConflict = !checkAvailability(
      { start: startTime, end: endTime },
      existingBookings.map((b) => ({ start: b.startTime, end: b.endTime })),
      teacher.bufferTime
    );

    if (hasConflict) {
      return NextResponse.json(
        { error: "This time slot is no longer available" },
        { status: 409 }
      );
    }

    // Get user timezone
    const user = await prisma.user.findUnique({
      where: { id: session.user.id },
    });

    // Calculate amount
    const amount = (teacher.hourlyRate / 60) * validatedData.durationMinutes;

    // Create booking with CONFIRMED status (mock payment)
    const booking = await prisma.booking.create({
      data: {
        studentId: session.user.id,
        teacherId: validatedData.teacherId,
        startTime,
        endTime,
        durationMinutes: validatedData.durationMinutes,
        notes: validatedData.notes,
        studentTimezone: user?.timezone || "UTC",
        teacherTimezone: teacher.user.timezone,
        status: "CONFIRMED", // Mock payment - directly confirmed
      },
      include: {
        student: {
          select: { id: true, name: true, email: true, image: true },
        },
        teacher: {
          select: { id: true, name: true, email: true, image: true },
        },
      },
    });

    // Create completed payment record (mock payment)
    await prisma.payment.create({
      data: {
        bookingId: booking.id,
        amount,
        status: "COMPLETED", // Mock payment - directly completed
        stripePaymentId: `mock_${booking.id}`, // Mock payment ID
      },
    });

    // Generate meeting link
    let meetingLink: string | undefined;
    try {
      meetingLink = await generateMeetingLink({
        id: booking.id,
        teacherId: validatedData.teacherId,
        startTime,
        endTime,
        teacher: {
          name: teacher.user.name,
          email: teacher.user.email,
        },
        student: {
          name: session.user.name ?? null,
          email: session.user.email ?? null,
        },
      });

      // Update booking with meeting link
      await prisma.booking.update({
        where: { id: booking.id },
        data: { meetingLink },
      });
    } catch (error) {
      console.error("Failed to generate meeting link:", error);
    }

    // Create confirmation notification
    await prisma.notification.create({
      data: {
        bookingId: booking.id,
        type: "BOOKING_CONFIRMED",
        scheduledAt: new Date(),
      },
    });

    // Create reminder notifications
    const reminderTimes = [
      { hours: 24, type: "REMINDER_24H" as const },
      { hours: 1, type: "REMINDER_1H" as const },
    ];

    for (const { hours, type } of reminderTimes) {
      const scheduledAt = new Date(startTime);
      scheduledAt.setHours(scheduledAt.getHours() - hours);

      if (scheduledAt > new Date()) {
        await prisma.notification.create({
          data: {
            bookingId: booking.id,
            type,
            scheduledAt,
          },
        });
      }
    }

    return NextResponse.json(
      {
        booking: {
          ...booking,
          meetingLink,
        },
        message: "Booking confirmed successfully (mock payment)",
      },
      { status: 201 }
    );
  } catch (error: any) {
    console.error("Error creating booking:", error);
    return NextResponse.json(
      { error: error.message || "Failed to create booking" },
      { status: 500 }
    );
  }
}
