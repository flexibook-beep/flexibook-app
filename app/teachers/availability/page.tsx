"use client"

import { useState, useEffect } from "react"
import { Navbar } from "@/components/navbar"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useToast } from "@/hooks/use-toast"
import { Trash2 } from "lucide-react"

const DAYS_OF_WEEK = [
  { value: 0, label: "Sunday" },
  { value: 1, label: "Monday" },
  { value: 2, label: "Tuesday" },
  { value: 3, label: "Wednesday" },
  { value: 4, label: "Thursday" },
  { value: 5, label: "Friday" },
  { value: 6, label: "Saturday" },
]

export default function TeacherAvailabilityPage() {
  const { toast } = useToast()
  const [availabilities, setAvailabilities] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [teacherId, setTeacherId] = useState("")
  const [formData, setFormData] = useState({
    dayOfWeek: 1,
    startTime: "09:00",
    endTime: "17:00",
    isRecurring: true,
  })

  useEffect(() => {
    fetchProfile()
  }, [])

  const fetchProfile = async () => {
    try {
      const response = await fetch("/api/teachers/profile")
      const data = await response.json()
      if (data.teacher) {
        setTeacherId(data.teacher.id)
        fetchAvailabilities(data.teacher.id)
      }
    } catch (error) {
      console.error("Failed to fetch profile:", error)
      setLoading(false)
    }
  }

  const fetchAvailabilities = async (id: string) => {
    try {
      const response = await fetch(`/api/availability?teacherId=${id}`)
      const data = await response.json()
      setAvailabilities(data.availabilities || [])
    } catch (error) {
      console.error("Failed to fetch availabilities:", error)
    } finally {
      setLoading(false)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    try {
      const response = await fetch("/api/availability", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      })

      if (!response.ok) throw new Error("Failed to add availability")

      toast({
        title: "Success",
        description: "Availability added successfully",
      })

      fetchAvailabilities(teacherId)
      setFormData({
        dayOfWeek: 1,
        startTime: "09:00",
        endTime: "17:00",
        isRecurring: true,
      })
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive",
      })
    }
  }

  const handleDelete = async (id: string) => {
    try {
      const response = await fetch(`/api/availability?id=${id}`, {
        method: "DELETE",
      })

      if (!response.ok) throw new Error("Failed to delete availability")

      toast({
        title: "Success",
        description: "Availability deleted",
      })

      fetchAvailabilities(teacherId)
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive",
      })
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen">
        <Navbar />
        <div className="container mx-auto px-8 py-12">
          <p className="text-gray-500 text-lg" style={{ fontFamily: "'Inter', sans-serif" }}>Loading...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen relative">
      <Navbar />
      {/* Full Screen Abstract Background */}
      <div className="fixed inset-0 -z-10 pointer-events-none">
        <div className="absolute inset-0" style={{
          background: `
            radial-gradient(circle at 15% 15%, rgba(236, 72, 153, 0.12) 0%, transparent 50%),
            radial-gradient(circle at 85% 85%, rgba(139, 92, 246, 0.15) 0%, transparent 50%),
            radial-gradient(circle at 50% 50%, rgba(59, 130, 246, 0.1) 0%, transparent 50%),
            linear-gradient(135deg, rgba(248, 250, 252, 0.8) 0%, rgba(255, 255, 255, 0.9) 100%)
          `
        }}></div>
        <div className="absolute inset-0" style={{
          backgroundImage: `
            repeating-linear-gradient(60deg, transparent, transparent 70px, rgba(236, 72, 153, 0.025) 70px, rgba(236, 72, 153, 0.025) 140px),
            repeating-linear-gradient(120deg, transparent, transparent 70px, rgba(139, 92, 246, 0.025) 70px, rgba(139, 92, 246, 0.025) 140px)
          `
        }}></div>
      </div>
      <div className="container mx-auto px-8 py-12 max-w-6xl">
        <div className="mb-12">
          <h1 className="text-5xl font-black text-gray-900 tracking-tight mb-3" style={{ fontFamily: "'Inter', sans-serif" }}>Manage Availability</h1>
          <p className="text-xl text-gray-600" style={{ fontFamily: "'Inter', sans-serif" }}>
            Set your weekly teaching schedule
          </p>
        </div>

        <div className="grid md:grid-cols-2 gap-8">
          <div className="backdrop-blur-xl bg-white/80 rounded-3xl shadow-2xl p-10 border border-gray-200/60">
            <div className="mb-8">
              <h3 className="text-2xl font-black text-gray-900 mb-2" style={{ fontFamily: "'Inter', sans-serif" }}>Add Availability</h3>
              <p className="text-gray-600" style={{ fontFamily: "'Inter', sans-serif" }}>Set when you&apos;re available to teach</p>
            </div>
            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="space-y-3">
                <Label htmlFor="dayOfWeek" className="text-base font-bold text-gray-900" style={{ fontFamily: "'Inter', sans-serif" }}>Day of Week</Label>
                <select
                  id="dayOfWeek"
                  className="flex h-12 w-full rounded-xl border-2 border-gray-200 bg-white px-4 py-2 text-base font-semibold focus:outline-none focus:ring-2 focus:ring-gray-400 focus:border-transparent transition-all duration-200"
                  style={{ fontFamily: "'Inter', sans-serif" }}
                  value={formData.dayOfWeek}
                  onChange={(e) =>
                    setFormData({ ...formData, dayOfWeek: parseInt(e.target.value) })
                  }
                >
                  {DAYS_OF_WEEK.map((day) => (
                    <option key={day.value} value={day.value}>
                      {day.label}
                    </option>
                  ))}
                </select>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-3">
                  <Label htmlFor="startTime" className="text-base font-bold text-gray-900" style={{ fontFamily: "'Inter', sans-serif" }}>Start Time</Label>
                  <Input
                    id="startTime"
                    type="time"
                    value={formData.startTime}
                    onChange={(e) =>
                      setFormData({ ...formData, startTime: e.target.value })
                    }
                    className="h-12 rounded-xl border-2 border-gray-200 text-base font-semibold"
                    style={{ fontFamily: "'Inter', sans-serif" }}
                    required
                  />
                </div>

                <div className="space-y-3">
                  <Label htmlFor="endTime" className="text-base font-bold text-gray-900" style={{ fontFamily: "'Inter', sans-serif" }}>End Time</Label>
                  <Input
                    id="endTime"
                    type="time"
                    value={formData.endTime}
                    onChange={(e) =>
                      setFormData({ ...formData, endTime: e.target.value })
                    }
                    className="h-12 rounded-xl border-2 border-gray-200 text-base font-semibold"
                    style={{ fontFamily: "'Inter', sans-serif" }}
                    required
                  />
                </div>
              </div>

              <Button 
                type="submit" 
                className="w-full bg-gradient-to-r from-gray-800 to-gray-900 hover:from-gray-900 hover:to-black text-white shadow-lg rounded-xl h-12 font-bold text-base transition-all duration-300"
                style={{ fontFamily: "'Inter', sans-serif" }}
              >
                Add Availability
              </Button>
            </form>
          </div>

          <div className="backdrop-blur-xl bg-white/80 rounded-3xl shadow-2xl p-10 border border-gray-200/60">
            <div className="mb-8">
              <h3 className="text-2xl font-black text-gray-900 mb-2" style={{ fontFamily: "'Inter', sans-serif" }}>Your Availability</h3>
              <p className="text-gray-600" style={{ fontFamily: "'Inter', sans-serif" }}>Manage your recurring schedule</p>
            </div>
            {availabilities.length === 0 ? (
              <p className="text-gray-500 text-center py-12 text-base" style={{ fontFamily: "'Inter', sans-serif" }}>
                No availability set yet
              </p>
            ) : (
              <div className="space-y-3">
                {availabilities.map((avail) => (
                  <div
                    key={avail.id}
                    className="flex items-center justify-between p-5 border-2 border-gray-200 rounded-2xl bg-gray-50/50 hover:bg-gray-100/50 transition-all duration-200"
                  >
                    <div>
                      <div className="font-black text-gray-900 text-base mb-1" style={{ fontFamily: "'Inter', sans-serif" }}>
                        {DAYS_OF_WEEK.find((d) => d.value === avail.dayOfWeek)?.label}
                      </div>
                      <div className="text-sm text-gray-600 font-semibold" style={{ fontFamily: "'Inter', sans-serif" }}>
                        {avail.startTime} - {avail.endTime}
                      </div>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleDelete(avail.id)}
                      className="hover:bg-red-50 rounded-xl transition-colors"
                    >
                      <Trash2 className="w-5 h-5 text-red-600" />
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

