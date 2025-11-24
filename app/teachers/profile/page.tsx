"use client"

import { useState, useEffect } from "react"
import { useRouter } from "next/navigation"
import { Navbar } from "@/components/navbar"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useToast } from "@/hooks/use-toast"

export default function TeacherProfilePage() {
  const router = useRouter()
  const { toast } = useToast()
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [formData, setFormData] = useState({
    bio: "",
    hourlyRate: 50,
    languages: [] as string[],
    yearsExperience: 0,
    bufferTime: 10,
    isActive: false
  })
  const [languageInput, setLanguageInput] = useState("")

  useEffect(() => {
    fetchProfile()
  }, [])

  const fetchProfile = async () => {
    try {
      const response = await fetch("/api/teachers/profile")
      const data = await response.json()
      if (data.teacher) {
        setFormData({
          bio: data.teacher.bio || "",
          hourlyRate: data.teacher.hourlyRate,
          languages: data.teacher.languages || [],
          yearsExperience: data.teacher.yearsExperience || 0,
          bufferTime: data.teacher.bufferTime,
          isActive: data.teacher.isActive || false,
        })
      }
    } catch (error) {
      console.error("Failed to fetch profile:", error)
    } finally {
      setLoading(false)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)

    try {
      const response = await fetch("/api/teachers/profile", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      })

      if (!response.ok) throw new Error("Failed to update profile")

      toast({
        title: "Success",
        description: "Profile updated successfully",
      })

      router.push("/dashboard")
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive",
      })
    } finally {
      setSaving(false)
    }
  }

  const addLanguage = () => {
    if (languageInput && !formData.languages.includes(languageInput)) {
      setFormData({
        ...formData,
        languages: [...formData.languages, languageInput],
      })
      setLanguageInput("")
    }
  }

  const removeLanguage = (lang: string) => {
    setFormData({
      ...formData,
      languages: formData.languages.filter((l) => l !== lang),
    })
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
            radial-gradient(circle at 70% 20%, rgba(147, 51, 234, 0.12) 0%, transparent 50%),
            radial-gradient(circle at 30% 70%, rgba(59, 130, 246, 0.15) 0%, transparent 50%),
            radial-gradient(circle at 60% 60%, rgba(99, 102, 241, 0.1) 0%, transparent 50%),
            linear-gradient(135deg, rgba(249, 250, 251, 0.8) 0%, rgba(255, 255, 255, 0.9) 100%)
          `
        }}></div>
        <div className="absolute inset-0" style={{
          backgroundImage: `
            repeating-linear-gradient(90deg, transparent, transparent 80px, rgba(147, 51, 234, 0.02) 80px, rgba(147, 51, 234, 0.02) 160px),
            repeating-linear-gradient(0deg, transparent, transparent 80px, rgba(59, 130, 246, 0.02) 80px, rgba(59, 130, 246, 0.02) 160px)
          `
        }}></div>
      </div>
      <div className="container mx-auto px-8 py-12 max-w-3xl">
        <div className="mb-12">
          <h1 className="text-5xl font-black text-gray-900 tracking-tight mb-3" style={{ fontFamily: "'Inter', sans-serif" }}>Teacher Profile</h1>
          <p className="text-xl text-gray-600" style={{ fontFamily: "'Inter', sans-serif" }}>
            Update your teaching profile information
          </p>
        </div>

        <div className="backdrop-blur-xl bg-white/80 rounded-3xl shadow-2xl p-10 border border-gray-200/60">
          <form onSubmit={handleSubmit} className="space-y-8">
            <div className="space-y-3">
              <Label htmlFor="bio" className="text-base font-bold text-gray-900" style={{ fontFamily: "'Inter', sans-serif" }}>Bio</Label>
              <textarea
                id="bio"
                className="flex min-h-[150px] w-full rounded-xl border-2 border-gray-200 bg-white px-4 py-3 text-base focus:outline-none focus:ring-2 focus:ring-gray-400 focus:border-transparent transition-all duration-200"
                style={{ fontFamily: "'Inter', sans-serif" }}
                placeholder="Tell students about yourself..."
                value={formData.bio}
                onChange={(e) => setFormData({ ...formData, bio: e.target.value })}
                maxLength={500}
              />
              <p className="text-sm text-gray-500 font-semibold" style={{ fontFamily: "'Inter', sans-serif" }}>
                {formData.bio.length}/500 characters
              </p>
            </div>

            <div className="space-y-3">
              <Label htmlFor="hourlyRate" className="text-base font-bold text-gray-900" style={{ fontFamily: "'Inter', sans-serif" }}>Hourly Rate (USD)</Label>
              <Input
                id="hourlyRate"
                type="number"
                min="5"
                max="500"
                value={formData.hourlyRate}
                onChange={(e) =>
                  setFormData({ ...formData, hourlyRate: parseFloat(e.target.value) })
                }
                className="h-12 rounded-xl border-2 border-gray-200 text-base font-semibold"
                style={{ fontFamily: "'Inter', sans-serif" }}
                required
              />
            </div>

            <div className="space-y-3">
              <Label className="text-base font-bold text-gray-900" style={{ fontFamily: "'Inter', sans-serif" }}>Languages You Teach</Label>
              <div className="flex gap-3">
                <Input
                  type="text"
                  placeholder="e.g. English, Spanish"
                  value={languageInput}
                  onChange={(e) => setLanguageInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      e.preventDefault()
                      addLanguage()
                    }
                  }}
                  className="h-12 rounded-xl border-2 border-gray-200 text-base"
                  style={{ fontFamily: "'Inter', sans-serif" }}
                />
                <Button
                  type="button"
                  onClick={addLanguage}
                  className="bg-gradient-to-r from-gray-800 to-gray-900 hover:from-gray-900 hover:to-black text-white rounded-xl px-8 font-bold h-12"
                  style={{ fontFamily: "'Inter', sans-serif" }}
                >
                  Add
                </Button>
              </div>
              <div className="flex flex-wrap gap-2 mt-3">
                {formData.languages.map((lang) => (
                  <span
                    key={lang}
                    className="bg-gray-100 text-gray-800 px-4 py-2 rounded-full text-sm font-bold flex items-center gap-2"
                    style={{ fontFamily: "'Inter', sans-serif" }}
                  >
                    {lang}
                    <button
                      type="button"
                      onClick={() => removeLanguage(lang)}
                      className="hover:text-red-600 font-bold text-lg transition-colors"
                    >
                      ×
                    </button>
                  </span>
                ))}
              </div>
            </div>

            <div className="space-y-3">
              <Label htmlFor="yearsExperience" className="text-base font-bold text-gray-900" style={{ fontFamily: "'Inter', sans-serif" }}>Years of Experience</Label>
              <Input
                id="yearsExperience"
                type="number"
                min="0"
                max="50"
                value={formData.yearsExperience}
                onChange={(e) =>
                  setFormData({ ...formData, yearsExperience: parseInt(e.target.value) })
                }
                className="h-12 rounded-xl border-2 border-gray-200 text-base font-semibold"
                style={{ fontFamily: "'Inter', sans-serif" }}
              />
            </div>

            <div className="space-y-3">
              <Label htmlFor="bufferTime" className="text-base font-bold text-gray-900" style={{ fontFamily: "'Inter', sans-serif" }}>Buffer Time Between Sessions (minutes)</Label>
              <Input
                id="bufferTime"
                type="number"
                min="0"
                max="60"
                value={formData.bufferTime}
                onChange={(e) =>
                  setFormData({ ...formData, bufferTime: parseInt(e.target.value) })
                }
                className="h-12 rounded-xl border-2 border-gray-200 text-base font-semibold"
                style={{ fontFamily: "'Inter', sans-serif" }}
              />
              <p className="text-sm text-gray-500 font-semibold" style={{ fontFamily: "'Inter', sans-serif" }}>
                Time to rest between back-to-back sessions
              </p>
            </div>

            <div className="space-y-3">
              <div className="flex items-center justify-between w-full">
                <Label htmlFor="isActive" className="text-base font-bold text-gray-900" style={{ fontFamily: "'Inter', sans-serif" }}>Active Status</Label>
                <button
                  type="button"
                  id="isActive"
                  aria-pressed={formData.isActive}
                  onClick={() => setFormData({ ...formData, isActive: !formData.isActive })}
                  className={`inline-flex items-center justify-center h-12 px-8 rounded-2xl font-bold text-base tracking-wide transition-colors duration-300 border-2 focus:outline-none focus:ring-2 focus:ring-gray-400 focus:ring-offset-2 ${formData.isActive ? 'bg-green-600 hover:bg-green-700 text-white border-green-700 shadow-lg' : 'bg-gray-200 hover:bg-gray-300 text-gray-800 border-gray-300'}`}
                  style={{ fontFamily: "'Inter', sans-serif" }}
                >
                  {formData.isActive ? 'Active' : 'Inactive'}
                </button>
              </div>
            </div>

            <div className="flex gap-4 pt-6">
              <Button
                type="submit"
                disabled={saving}
                className="bg-gradient-to-r from-gray-800 to-gray-900 hover:from-gray-900 hover:to-black text-white shadow-lg rounded-xl px-10 h-12 font-bold text-base transition-all duration-300"
                style={{ fontFamily: "'Inter', sans-serif" }}
              >
                {saving ? "Saving..." : "Save Changes"}
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={() => router.push("/dashboard")}
                className="border-2 border-gray-300 hover:border-gray-500 bg-white hover:bg-gray-50 text-gray-700 rounded-xl px-10 h-12 font-bold text-base transition-all duration-300"
                style={{ fontFamily: "'Inter', sans-serif" }}
              >
                Cancel
              </Button>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}

