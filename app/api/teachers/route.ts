import { NextRequest, NextResponse } from "next/server"
import { getServerSession } from "next-auth"
import { authOptions } from "@/lib/auth"
import { prisma } from "@/lib/prisma"

export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  try {
    // Check if the user is logged in
    const session = await getServerSession(authOptions)
    if (!session?.user?.id) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
    }

    // Optionally, you can read search params to filter teachers
    const searchParams = req.nextUrl.searchParams
    const language = searchParams.get("language")
    const minRate = searchParams.get("minRate")
    const maxRate = searchParams.get("maxRate")

    const teachers = await prisma.teacher.findMany({
      where: {
        isActive: true,
        ...(language && {
          languages: {
            has: language,
          },
        }),
        ...(minRate && {
          hourlyRate: {
            gte: parseFloat(minRate),
          },
        }),
        ...(maxRate && {
          hourlyRate: {
            lte: parseFloat(maxRate),
          },
        }),
      },
      include: {
        user: {
          select: {
            id: true,
            name: true,
            image: true,
            email: true,
          },
        },
      },
      orderBy: {
        createdAt: "desc",
      },
    })

    return NextResponse.json({ teachers })
  } catch (error) {
    console.error("Error fetching teachers:", error)
    return NextResponse.json(
      { error: "Failed to fetch teachers" },
      { status: 500 }
    )
  }
}
