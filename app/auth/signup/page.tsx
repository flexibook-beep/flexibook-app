"use client";

import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardHeader,
  CardTitle,
  CardContent,
} from "@/components/ui/card";

export default function SignUpPage() {
  const router = useRouter();

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="text-2xl font-bold text-center">
            Join Flexibook
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col space-y-4">
          <Button
            onClick={() => router.push("/auth/signup/student")}
            className="w-full bg-gradient-to-r from-gray-700 to-gray-800 hover:from-gray-800 hover:to-gray-900 text-white shadow-2xl shadow-gray-400/30 rounded-2xl px-12 h-16 text-lg font-bold hover:shadow-gray-500/40 hover:-translate-y-0.5 transition-all duration-300"
            style={{ fontFamily: "'Inter', sans-serif", fontWeight: 700 }}
          >
            I'm a Student
          </Button>
          <Button
            onClick={() => router.push("/auth/signup/teacher")}
            className="w-full bg-white border-2 border-gray-300 text-gray-700 hover:bg-gray-50 hover:border-gray-500 rounded-2xl px-12 h-16 text-lg font-bold shadow-lg hover:shadow-xl hover:-translate-y-0.5 transition-all duration-300"
            style={{ fontFamily: "'Inter', sans-serif", fontWeight: 700 }}
          >
            I'm a Teacher
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
