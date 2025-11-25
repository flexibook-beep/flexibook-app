import { NextResponse } from "next/server"
import { getServerSession } from "next-auth"
import { authOptions } from "@/lib/auth"
import { prisma } from "@/lib/prisma"
import { z } from "zod"

const rescheduleSchema = z.object({
  newStartTime: z.string().datetime(),
  newDurationMinutes: z.number().min(20).max(90),
  reason: z.string().min(10, "Please provide a reason for rescheduling"),
})

export async function POST(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    const session = await getServerSession(authOptions)
    if (!session?.user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
    }

    const bookingId = params.id
    const body = await request.json()
    const { newStartTime, newDurationMinutes, reason } = rescheduleSchema.parse(body)

    // Get the original booking
    const booking = await prisma.booking.findUnique({
      where: { id: bookingId },
      include: {
        teacher: true,
        student: true,
      },
    })

    if (!booking) {
      return NextResponse.json({ error: "Booking not found" }, { status: 404 })
    }

    // Check if user is authorized (either student or teacher)
    if (
      booking.studentId !== session.user.id &&
      booking.teacherId !== session.user.id
    ) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 403 })
    }

    // Calculate new end time
    const startTime = new Date(newStartTime)
    const endTime = new Date(startTime.getTime() + newDurationMinutes * 60000)

    // Check if new time slot conflicts with existing bookings
    const conflictingBooking = await prisma.booking.findFirst({
      where: {
        teacherId: booking.teacherId,
        status: "CONFIRMED",
        id: { not: bookingId },
        OR: [
          {
            AND: [
              { startTime: { lte: startTime } },
              { endTime: { gt: startTime } },
            ],
          },
          {
            AND: [
              { startTime: { lt: endTime } },
              { endTime: { gte: endTime } },
            ],
          },
          {
            AND: [
              { startTime: { gte: startTime } },
              { endTime: { lte: endTime } },
            ],
          },
        ],
      },
    })

    if (conflictingBooking) {
      return NextResponse.json(
        { error: "This time slot is already booked" },
        { status: 409 }
      )
    }

    // Check teacher availability
    const dayOfWeek = startTime.getDay() // 0-6 (Sunday = 0)
    const timeStr = startTime.toTimeString().substring(0, 5) // HH:mm
    
    // Get teacher's user id for availability check
    const teacherProfile = await prisma.teacher.findUnique({
      where: { userId: booking.teacherId },
    })

    if (!teacherProfile) {
      return NextResponse.json(
        { error: "Teacher profile not found" },
        { status: 404 }
      )
    }

    const availability = await prisma.availability.findFirst({
      where: {
        teacherId: teacherProfile.id,
        dayOfWeek,
        isRecurring: true,
        startTime: { lte: timeStr },
        endTime: { gte: timeStr },
      },
    })

    if (!availability) {
      return NextResponse.json(
        { error: "Teacher is not available at this time" },
        { status: 400 }
      )
    }

    // Update the booking
    const updatedBooking = await prisma.booking.update({
      where: { id: bookingId },
      data: {
        startTime,
        endTime,
        durationMinutes: newDurationMinutes,
        status: "RESCHEDULED",
        cancelReason: reason,
      },
      include: {
        teacher: true,
        student: true,
        payment: true,
      },
    })

    // Send notification emails
    try {
      const { sendRescheduleEmail } = await import("@/lib/email")
      await sendRescheduleEmail(
        {
          studentName: booking.student.name!,
          teacherName: booking.teacher.name!,
          startTime: startTime.toISOString(),
          durationMinutes: newDurationMinutes,
          studentEmail: booking.student.email!,
          teacherEmail: booking.teacher.email!,
        },
        reason
      )
    } catch (error) {
      console.error("Failed to send reschedule email:", error)
    }

    return NextResponse.json(updatedBooking)
  } catch (error) {
    console.error("Reschedule booking error:", error)
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Invalid input", details: error.errors },
        { status: 400 }
      )
    }
    return NextResponse.json(
      { error: "Failed to reschedule booking" },
      { status: 500 }
    )
  }
}
