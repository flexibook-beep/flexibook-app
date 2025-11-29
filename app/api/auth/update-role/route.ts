import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { z } from "zod";

const updateRoleSchema = z.object({
  email: z.string().email(),
  role: z.enum(["STUDENT", "TEACHER"]),
});

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const validatedData = updateRoleSchema.parse(body);

    const user = await prisma.user.update({
      where: { email: validatedData.email },
      data: { role: validatedData.role },
    });

    // If role is TEACHER, create teacher profile
    if (validatedData.role === "TEACHER") {
      await prisma.teacher.create({
        data: {
          userId: user.id,
          hourlyRate: 50, // default rate
          languages: ["English"],
          isActive: false, // require profile completion
        },
      });
    }

    return NextResponse.json(
      {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
        },
      },
      { status: 200 }
    );
  } catch (error: any) {
    console.error("Update role error:", error);
    return NextResponse.json(
      { error: error.message || "Something went wrong" },
      { status: 500 }
    );
  }
}
