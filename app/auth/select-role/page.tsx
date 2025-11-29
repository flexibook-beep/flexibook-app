"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useSession } from "next-auth/react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardHeader,
  CardTitle,
  CardContent,
} from "@/components/ui/card";

export default function SelectRolePage() {
  const router = useRouter();
  const { data: session, status, update } = useSession();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleRoleSelection = async (role: "STUDENT" | "TEACHER") => {
    setLoading(true);
    setError(null);

    if (status !== "authenticated" || !session?.user?.email) {
      setError("Something went wrong. Please try again.");
      setLoading(false);
      return;
    }

    const response = await fetch("/api/auth/update-role", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email: session.user.email,
        role,
      }),
    });

    if (response.ok) {
      // Update the session with the new role
      await update({ role });

      if (role === "TEACHER") {
        router.push("/teachers/profile");
      } else {
        router.push("/dashboard");
      }
    } else {
      const data = await response.json();
      setError(data.message || "Something went wrong");
    }

    setLoading(false);
  };

  if (status === "loading") {
    return (
      <div className="flex items-center justify-center min-h-screen">
        Loading...
      </div>
    );
  }

  if (status === "unauthenticated") {
    router.push("/auth/signin");
    return null;
  }

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="text-2xl font-bold text-center">
            Choose Your Role
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col space-y-4">
          <p className="text-center text-gray-600">
            Are you a student looking to learn, or a teacher wanting to share
            your knowledge?
          </p>
          <Button
            onClick={() => handleRoleSelection("STUDENT")}
            className="w-full"
            disabled={loading || status !== "authenticated"}
          >
            I'm a Student
          </Button>
          <Button
            onClick={() => handleRoleSelection("TEACHER")}
            className="w-full"
            disabled={loading || status !== "authenticated"}
          >
            I'm a Teacher
          </Button>
          {error && <p className="text-sm text-red-500">{error}</p>}
        </CardContent>
      </Card>
    </div>
  );
}
