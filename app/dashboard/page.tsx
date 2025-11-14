import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { redirect } from "next/navigation";
import { Navbar } from "@/components/navbar";
import { StudentDashboard } from "@/components/dashboard/student-dashboard";
import { TeacherDashboard } from "@/components/dashboard/teacher-dashboard";

export default async function DashboardPage() {
  // REAL AUTH (uncomment this when auth is implemented)
  /*
  const session = await getServerSession(authOptions);

  if (!session) {
    redirect("/auth/signin");
  }
  */

  // TEMPORARY FAKE SESSION (delete this entire block after auth works)
  const session = {
    user: {
      role: "STUDENT", // or "TEACHER"
    },
  };

  return (
    <div className="min-h-screen relative">
      <Navbar />

      {/* Full Screen Abstract Background */}
      <div className="fixed inset-0 -z-10 pointer-events-none">
        <div
          className="absolute inset-0"
          style={{
            background:
              session.user.role === "STUDENT"
                ? `
              radial-gradient(circle at 35% 25%, rgba(59, 130, 246, 0.15) 0%, transparent 50%),
              radial-gradient(circle at 70% 75%, rgba(139, 92, 246, 0.12) 0%, transparent 50%),
              radial-gradient(circle at 45% 65%, rgba(99, 102, 241, 0.1) 0%, transparent 50%),
              linear-gradient(135deg, rgba(249, 250, 252, 0.8) 0%, rgba(255, 255, 255, 0.9) 100%)
            `
                : `
              radial-gradient(circle at 25% 35%, rgba(168, 85, 247, 0.15) 0%, transparent 50%),
              radial-gradient(circle at 75% 65%, rgba(99, 102, 241, 0.12) 0%, transparent 50%),
              radial-gradient(circle at 50% 50%, rgba(59, 130, 246, 0.1) 0%, transparent 50%),
              linear-gradient(135deg, rgba(248, 249, 251, 0.8) 0%, rgba(255, 255, 255, 0.9) 100%)
            `,
          }}
        ></div>

        <div
          className="absolute inset-0"
          style={{
            backgroundImage: `
            repeating-linear-gradient(60deg, transparent, transparent 65px, rgba(99, 102, 241, 0.025) 65px, rgba(99, 102, 241, 0.025) 130px),
            repeating-linear-gradient(-60deg, transparent, transparent 65px, rgba(168, 85, 247, 0.025) 65px, rgba(168, 85, 247, 0.025) 130px)
          `,
          }}
        ></div>
      </div>

      <main className="container mx-auto px-4 py-8">
        {session.user.role === "STUDENT" && <StudentDashboard />}
        {session.user.role === "TEACHER" && <TeacherDashboard />}
      </main>
    </div>
  );
}
