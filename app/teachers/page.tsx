"use client"

import { useEffect, useState } from "react"
import { useSession } from "next-auth/react"
import { useRouter } from "next/navigation"
import Link from "next/link"
import { Navbar } from "@/components/navbar"
import { Button } from "@/components/ui/button"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { formatCurrency } from "@/lib/utils"
import { Star } from "lucide-react"

export default function TeachersPage() {
  const { data: session, status } = useSession()
  const router = useRouter()
  const [teachers, setTeachers] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (status === "loading") return

    // Redirect teachers to their dashboard
    if (session?.user.role === "TEACHER") {
      router.push("/dashboard")
      return
    }

    fetchTeachers()
  }, [session, status, router])

  const fetchTeachers = async () => {
    try {
      const response = await fetch("/api/teachers")
      const data = await response.json()
      setTeachers(data.teachers || [])
    } catch (error) {
      console.error("Failed to fetch teachers:", error)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen relative">
      <Navbar />
      {/* Full Screen Abstract Background */}
      <div className="fixed inset-0 -z-10 pointer-events-none">
        <div className="absolute inset-0" style={{
          background: `
            radial-gradient(circle at 20% 30%, rgba(99, 102, 241, 0.15) 0%, transparent 50%),
            radial-gradient(circle at 80% 70%, rgba(168, 85, 247, 0.12) 0%, transparent 50%),
            radial-gradient(circle at 40% 80%, rgba(59, 130, 246, 0.1) 0%, transparent 50%),
            linear-gradient(135deg, rgba(243, 244, 246, 0.8) 0%, rgba(255, 255, 255, 0.9) 100%)
          `
        }}></div>
        <div className="absolute inset-0" style={{
          backgroundImage: `
            repeating-linear-gradient(45deg, transparent, transparent 60px, rgba(99, 102, 241, 0.03) 60px, rgba(99, 102, 241, 0.03) 120px),
            repeating-linear-gradient(-45deg, transparent, transparent 60px, rgba(168, 85, 247, 0.02) 60px, rgba(168, 85, 247, 0.02) 120px)
          `
        }}></div>
      </div>
      <div className="container mx-auto px-8 py-12">
        <div className="mb-12">
          <h1 className="text-5xl font-black text-gray-900 tracking-tight mb-3" style={{ fontFamily: "'Inter', sans-serif" }}>Find Your Teacher</h1>
          <p className="text-xl text-gray-600" style={{ fontFamily: "'Inter', sans-serif" }}>
            Browse our qualified language teachers
          </p>
        </div>

        {/* Breadcrumb navigation */}
        <div className="mb-8 text-sm text-gray-500 flex items-center gap-2" style={{ fontFamily: "'Inter', sans-serif" }}>
          <span
            className="hover:underline cursor-pointer"
            onClick={() => router.push("/dashboard?role=student")}
          >
            Dashboard
          </span>
          <span>/</span>
          <span className="font-semibold text-gray-900">Teachers</span>
        </div>

        {loading ? (
          <div className="text-center py-20">
            <p className="text-gray-500 text-lg" style={{ fontFamily: "'Inter', sans-serif" }}>Loading teachers...</p>
          </div>
        ) : teachers.length === 0 ? (
          <div className="text-center py-20">
            <p className="text-gray-500 text-lg" style={{ fontFamily: "'Inter', sans-serif" }}>No teachers available yet</p>
          </div>
        ) : (
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
            {teachers.map((teacher) => {
              const initials = teacher.user.name
                ?.split(" ")
                .map((n: string) => n[0])
                .join("")
                .toUpperCase() || "T"

              return (
                <div key={teacher.id} className="backdrop-blur-xl bg-white/80 rounded-3xl shadow-lg border border-gray-200/60 p-8 hover:shadow-2xl transition-all duration-300 group">
                  <div className="flex items-start gap-5 mb-6">
                    <Avatar className="w-20 h-20 ring-4 ring-gray-100 group-hover:ring-gray-200 transition-all duration-300">
                      <AvatarImage src={teacher.user.image || undefined} />
                      <AvatarFallback className="text-2xl font-black bg-gradient-to-br from-gray-800 to-gray-900 text-white" style={{ fontFamily: "'Inter', sans-serif" }}>{initials}</AvatarFallback>
                    </Avatar>
                    <div className="flex-1">
                      <h3 className="text-2xl font-black text-gray-900 mb-1" style={{ fontFamily: "'Inter', sans-serif" }}>{teacher.user.name}</h3>
                      <p className="text-sm text-gray-600 font-semibold flex items-center gap-1" style={{ fontFamily: "'Inter', sans-serif" }}>
                        <Star className="w-4 h-4 fill-yellow-400 stroke-yellow-400" />
                        {teacher.yearsExperience
                          ? `${teacher.yearsExperience} years experience`
                          : "Experienced teacher"}
                      </p>
                    </div>
                  </div>

                  <div className="mb-6">
                    <p className="text-sm text-gray-600 line-clamp-3 leading-relaxed" style={{ fontFamily: "'Inter', sans-serif" }}>
                      {teacher.bio || "Professional language teacher"}
                    </p>
                  </div>

                  <div className="flex flex-wrap gap-2 mb-6">
                    {teacher.languages.slice(0, 3).map((lang: string) => (
                      <span key={lang} className="px-3 py-1 text-xs font-bold bg-gray-100 text-gray-800 rounded-full" style={{ fontFamily: "'Inter', sans-serif" }}>
                        {lang}
                      </span>
                    ))}
                  </div>

                  <div className="flex items-center justify-between pt-6 border-t border-gray-200">
                    <div>
                      <div className="text-3xl font-black text-gray-900" style={{ fontFamily: "'Inter', sans-serif" }}>
                        {formatCurrency(teacher.hourlyRate)}
                      </div>
                      <div className="text-xs text-gray-500 font-semibold" style={{ fontFamily: "'Inter', sans-serif" }}>per hour</div>
                    </div>
                    <Link href={`/teachers/${teacher.user.id}/book`}>
                      <Button className="bg-gradient-to-r from-gray-800 to-gray-900 hover:from-gray-900 hover:to-black text-white shadow-lg rounded-xl px-6 py-5 font-bold transition-all duration-300" style={{ fontFamily: "'Inter', sans-serif" }}>Book Lesson</Button>
                    </Link>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

