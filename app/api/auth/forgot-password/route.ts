import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { z } from "zod";
import { Resend } from "resend";

// Conditionally initialize Resend only if the API key is available.
const resend = process.env.RESEND_API_KEY
  ? new Resend(process.env.RESEND_API_KEY)
  : null;

const forgotPasswordSchema = z.object({
  email: z.string().email(),
});

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const validatedData = forgotPasswordSchema.parse(body);

    const user = await prisma.user.findUnique({
      where: { email: validatedData.email },
    });

    if (!user) {
      // For security reasons, don't reveal if the user doesn't exist.
      // We still return a success message to prevent email enumeration.
      return NextResponse.json(
        { message: "If an account with that email exists, we've sent a password reset link." },
        { status: 200 }
      );
    }

    // Generate a password reset token
    const token = crypto.randomUUID();
    const expires = new Date(Date.now() + 3600 * 1000); // Token valid for 1 hour

    await prisma.verificationToken.create({
      data: {
        identifier: user.email,
        token: token,
        expires: expires,
      },
    });

    // Send email with reset link
    const resetLink = `${process.env.NEXTAUTH_URL}/auth/reset-password?token=${token}`;

    // Only attempt to send an email if Resend is configured.
    if (resend) {
      await resend.emails.send({
        from: 'onboarding@resend.dev', // IMPORTANT: Replace with your verified sender domain in Resend
        to: user.email,
        subject: 'Reset your Flexibook password',
        html: `<p>Click <a href="${resetLink}">here</a> to reset your password.</p>`,
      });
    } else {
      // If Resend is not configured, log the link to the console for development/testing.
      // This prevents the build from failing in production if the API key is not set.
      console.log("Password reset link (Resend not configured):", resetLink);
    }

    return NextResponse.json(
      { message: "If an account with that email exists, we've sent a password reset link." },
      { status: 200 }
    );
  } catch (error: any) {
    console.error("Forgot password error:", error);
    return NextResponse.json(
      { error: error.message || "Something went wrong" },
      { status: 500 }
    );
  }
}
