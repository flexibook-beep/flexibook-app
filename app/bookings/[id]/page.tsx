"use client"

import { useEffect, useState } from "react"
import { useParams, useRouter, useSearchParams } from "next/navigation"
import { Navbar } from "@/components/navbar"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { useToast } from "@/hooks/use-toast"
import { format, addDays } from "date-fns"
import { formatCurrency, formatDuration } from "@/lib/utils"
import { Calendar, Clock, DollarSign, Video, ArrowLeft, CalendarClock } from "lucide-react"

const STATUS_CONFIG: Record<string, { bg: string, text: string, label: string }> = {
  PENDING_PAYMENT: { bg: "bg-yellow-100", text: "text-yellow-800", label: "Pending Payment" },
  CONFIRMED: { bg: "bg-green-100", text: "text-green-800", label: "Confirmed" },
  COMPLETED: { bg: "bg-blue-100", text: "text-blue-800", label: "Completed" },
  CANCELLED: { bg: "bg-red-100", text: "text-red-800", label: "Cancelled" },
  RESCHEDULED: { bg: "bg-purple-100", text: "text-purple-800", label: "Rescheduled" },
  REFUNDED: { bg: "bg-gray-100", text: "text-gray-800", label: "Refunded" },
}

export default function BookingDetailPage() {
  const params = useParams()
  const router = useRouter()
  const searchParams = useSearchParams()
  const { toast } = useToast()
  const [booking, setBooking] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [processing, setProcessing] = useState(false)
  const [rescheduleOpen, setRescheduleOpen] = useState(false)
  const [rescheduleData, setRescheduleData] = useState({
    newDate: "",
    newTime: "",
    duration: 45,
    reason: ""
  })

  const bookingId = params.id as string
  const paymentSuccess = searchParams.get("success") === "true"
  const paymentCancelled = searchParams.get("cancelled") === "true"

  useEffect(() => {
    fetchBooking()

    if (paymentSuccess) {
      toast({
        title: "Payment Successful!",
        description: "Your booking has been confirmed",
      })
    } else if (paymentCancelled) {
      toast({
        title: "Payment Cancelled",
        description: "You can retry payment anytime before the session",
        variant: "destructive",
      })
    }
  }, [])

  const fetchBooking = async () => {
    try {
      const response = await fetch(`/api/bookings/${bookingId}`)
      const data = await response.json()
      setBooking(data.booking)
    } catch (error) {
      console.error("Failed to fetch booking:", error)
    } finally {
      setLoading(false)
    }
  }

  const handlePayment = async () => {
    setProcessing(true)
    try {
      const response = await fetch("/api/payments/create-checkout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ bookingId }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || "Failed to create checkout session")
      }

      window.location.href = data.url
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive",
      })
      setProcessing(false)
    }
  }

  const handleCancel = async () => {
    if (!confirm("Are you sure you want to cancel this booking?")) return

    setProcessing(true)
    try {
      const response = await fetch(`/api/bookings/${bookingId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          status: "CANCELLED",
          cancelReason: "Cancelled by user",
        }),
      })

      if (!response.ok) throw new Error("Failed to cancel booking")

      toast({
        title: "Booking Cancelled",
        description: "Your booking has been cancelled",
      })

      fetchBooking()
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive",
      })
    } finally {
      setProcessing(false)
    }
  }

  const handleReschedule = async () => {
    if (!rescheduleData.newDate || !rescheduleData.newTime || !rescheduleData.reason) {
      toast({
        title: "Error",
        description: "Please fill in all fields",
        variant: "destructive",
      })
      return
    }

    if (rescheduleData.reason.length < 10) {
      toast({
        title: "Error",
        description: "Please provide a detailed reason (at least 10 characters)",
        variant: "destructive",
      })
      return
    }

    setProcessing(true)
    try {
      const newStartTime = new Date(`${rescheduleData.newDate}T${rescheduleData.newTime}`)
      
      const response = await fetch(`/api/bookings/${bookingId}/reschedule`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          newStartTime: newStartTime.toISOString(),
          newDurationMinutes: rescheduleData.duration,
          reason: rescheduleData.reason,
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || "Failed to reschedule booking")
      }

      toast({
        title: "Booking Rescheduled",
        description: "Your booking has been successfully rescheduled",
      })

      setRescheduleOpen(false)
      setRescheduleData({ newDate: "", newTime: "", duration: 45, reason: "" })
      fetchBooking()
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive",
      })
    } finally {
      setProcessing(false)
    }
  }

  if (loading || !booking) {
    return (
      <div className="min-h-screen">
        <Navbar />
        <div className="container mx-auto px-8 py-12">
          <p className="text-gray-500 text-lg" style={{ fontFamily: "'Inter', sans-serif" }}>Loading...</p>
        </div>
      </div>
    )
  }

  const status = STATUS_CONFIG[booking.status] || STATUS_CONFIG.PENDING_PAYMENT

  return (
    <div className="min-h-screen relative">
      <Navbar />

      {/* Background layers (unchanged) */}
      <div className="fixed inset-0 -z-10 pointer-events-none">
        <div className="absolute inset-0" style={{
          background: `
            radial-gradient(circle at 25% 75%, rgba(16, 185, 129, 0.12) 0%, transparent 50%),
            radial-gradient(circle at 75% 25%, rgba(99, 102, 241, 0.15) 0%, transparent 50%),
            radial-gradient(circle at 50% 50%, rgba(59, 130, 246, 0.1) 0%, transparent 50%),
            linear-gradient(135deg, rgba(247, 249, 252, 0.8) 0%, rgba(255, 255, 255, 0.9) 100%)
          `
        }}></div>
        <div className="absolute inset-0" style={{
          backgroundImage: `
            repeating-linear-gradient(45deg, transparent, transparent 75px, rgba(16, 185, 129, 0.025) 75px, rgba(16, 185, 129, 0.025) 150px),
            repeating-linear-gradient(-45deg, transparent, transparent 75px, rgba(99, 102, 241, 0.025) 75px, rgba(99, 102, 241, 0.025) 150px)
          `
        }}></div>
      </div>

      <div className="mx-auto px-4 sm:px-6 md:px-8 lg:px-12 max-w-full lg:max-w-5xl">
        <div className="pt-8 pb-12">
          <Button 
            variant="outline" 
            onClick={() => router.back()}
            className="mb-6 border-2 border-gray-300 hover:border-gray-500 bg-white hover:bg-gray-50 text-gray-700 rounded-xl px-5 h-10 font-bold text-sm md:text-base transition-all duration-300"
            style={{ fontFamily: "'Inter', sans-serif" }}
          >
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back
          </Button>

          <div className="backdrop-blur-xl bg-white/80 rounded-3xl shadow-2xl border border-gray-200/60 overflow-visible">
            {/* Header */}
            <div className="bg-gradient-to-r from-gray-50 to-gray-100 p-6 md:p-10 border-b border-gray-200">
              <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                <div className="w-full md:flex-1">
                  <h1 className="text-3xl md:text-4xl font-black text-gray-900 mb-2" style={{ fontFamily: "'Inter', sans-serif" }}>Booking Details</h1>
                  <p className="text-gray-600 font-semibold mb-3" style={{ fontFamily: "'Inter', sans-serif" }}>ID: {booking.id.substring(0, 8)}...</p>

                  {/* Mobile / small screens: status shown under title (visible on small only) */}
                  <div className="block md:hidden mt-1">
                    <span className={`${status.bg} ${status.text} px-4 py-2 rounded-full text-sm font-bold inline-block`} style={{ fontFamily: "'Inter', sans-serif" }}>
                      {status.label}
                    </span>
                  </div>
                </div>

                {/* Desktop / tablet badge (kept to the right on md+ screens) */}
                <div className="hidden md:flex md:items-center md:justify-end w-auto" style={{ minWidth: 160 }}>
                  <div className="flex items-center justify-end">
                    <span className={`${status.bg} ${status.text} px-5 py-2 rounded-full text-sm font-bold`} style={{ fontFamily: "'Inter', sans-serif", whiteSpace: "nowrap" }}>
                      {status.label}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Main content area */}
            <div className="p-6 md:p-10 space-y-6 md:space-y-8">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 md:gap-8">
                <div>
                  <h3 className="text-lg md:text-xl font-black text-gray-900 mb-4" style={{ fontFamily: "'Inter', sans-serif" }}>Teacher Information</h3>
                  <div className="space-y-3 text-base">
                    <p className="font-semibold text-gray-700" style={{ fontFamily: "'Inter', sans-serif" }}>
                      <span className="text-gray-500">Name:</span> {booking.teacher.name}
                    </p>
                    <p className="font-semibold text-gray-700" style={{ fontFamily: "'Inter', sans-serif" }}>
                      <span className="text-gray-500">Email:</span> {booking.teacher.email}
                    </p>
                  </div>
                </div>

                <div>
                  <h3 className="text-lg md:text-xl font-black text-gray-900 mb-4" style={{ fontFamily: "'Inter', sans-serif" }}>Session Details</h3>
                  <div className="space-y-3">
                    <div className="flex items-center gap-3 text-base text-gray-700" style={{ fontFamily: "'Inter', sans-serif" }}>
                      <Calendar className="w-5 h-5 text-gray-600" />
                      <span className="font-semibold">{format(new Date(booking.startTime), "PPPP")}</span>
                    </div>
                    <div className="flex items-center gap-3 text-base text-gray-700" style={{ fontFamily: "'Inter', sans-serif" }}>
                      <Clock className="w-5 h-5 text-gray-600" />
                      <span className="font-semibold">
                        {format(new Date(booking.startTime), "p")} - {format(new Date(booking.endTime), "p")}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 text-base text-gray-700" style={{ fontFamily: "'Inter', sans-serif" }}>
                      <Clock className="w-5 h-5 text-gray-600" />
                      <span className="font-semibold">Duration: {formatDuration(booking.durationMinutes)}</span>
                    </div>

                    {/* Status shown inside session details as well (always visible, but small) */}
                    <div className="mt-3">
                      <span className={`${status.bg} ${status.text} px-3 py-1 rounded-full text-xs font-bold inline-block`} style={{ fontFamily: "'Inter', sans-serif" }}>
                        {status.label}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {booking.meetingLink && booking.status === "CONFIRMED" && (
                <div className="p-4 md:p-6 bg-gradient-to-br from-blue-50 to-indigo-50 rounded-2xl border border-blue-200">
                  <div className="flex items-start gap-4">
                    <Video className="w-6 h-6 text-blue-600 mt-1" />
                    <div className="flex-1">
                      <h3 className="font-black text-gray-900 mb-2 text-base md:text-lg" style={{ fontFamily: "'Inter', sans-serif" }}>Meeting Link</h3>
                      <a
                        href={booking.meetingLink}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-600 hover:text-blue-700 hover:underline font-semibold text-sm md:text-base break-all transition-colors"
                        style={{ fontFamily: "'Inter', sans-serif" }}
                      >
                        {booking.meetingLink}
                      </a>
                    </div>
                  </div>
                </div>
              )}

              {booking.notes && (
                <div>
                  <h3 className="text-lg md:text-xl font-black text-gray-900 mb-3" style={{ fontFamily: "'Inter', sans-serif" }}>Notes</h3>
                  <p className="text-base text-gray-600 font-medium leading-relaxed" style={{ fontFamily: "'Inter', sans-serif" }}>{booking.notes}</p>
                </div>
              )}

              <div className="p-4 md:p-6 bg-gradient-to-br from-gray-50 to-gray-100 rounded-2xl border-2 border-gray-200">
                <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                  <div>
                    <p className="text-sm text-gray-500 mb-2 font-semibold" style={{ fontFamily: "'Inter', sans-serif" }}>Payment Amount</p>
                    <div className="flex items-center gap-2">
                      <DollarSign className="w-6 h-6 text-gray-600" />
                      <span className="text-2xl md:text-4xl font-black text-gray-900" style={{ fontFamily: "'Inter', sans-serif" }}>
                        {formatCurrency(booking.payment?.amount || 0)}
                      </span>
                    </div>
                  </div>
                  <div className="ml-auto md:ml-0">
                    <span className={`${status.bg} ${status.text} px-4 py-2 rounded-full text-sm font-bold`} style={{ fontFamily: "'Inter', sans-serif" }}>
                      {booking.payment?.status || "PENDING"}
                    </span>
                  </div>
                </div>
              </div>

              {/* Action buttons (stacked on mobile, row on md+) */}
              <div className="flex flex-col md:flex-row gap-4 pt-2 items-center md:items-start">
                {booking.status === "PENDING_PAYMENT" && (
                  <>
                    <Button
                      onClick={handlePayment}
                      disabled={processing}
                      className="w-full md:flex-1 bg-gradient-to-r from-gray-800 to-gray-900 hover:from-gray-900 hover:to-black text-white shadow-lg rounded-xl h-12 font-bold text-base transition-all duration-300"
                      style={{ fontFamily: "'Inter', sans-serif" }}
                    >
                      {processing ? "Processing..." : "Proceed to Payment"}
                    </Button>
                    <Button
                      variant="outline"
                      onClick={handleCancel}
                      disabled={processing}
                      className="w-full md:w-auto border-2 border-red-300 hover:border-red-500 bg-white hover:bg-red-50 text-red-600 rounded-xl px-8 h-12 font-bold text-base transition-all duration-300"
                      style={{ fontFamily: "'Inter', sans-serif" }}
                    >
                      Cancel Booking
                    </Button>
                  </>
                )}

                {(booking.status === "CONFIRMED" || booking.status === 'RESCHEDULED') &&
                  new Date(booking.startTime) > new Date() && (
                    <>
                      <Dialog open={rescheduleOpen} onOpenChange={setRescheduleOpen}>
                        <DialogTrigger asChild>
                          <Button
                            className="w-full md:flex-1 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 text-white shadow-lg rounded-xl px-8 h-12 font-bold text-base transition-all duration-300"
                            style={{ fontFamily: "'Inter', sans-serif" }}
                          >
                            <CalendarClock className="w-5 h-5 mr-2" />
                            Reschedule
                          </Button>
                        </DialogTrigger>
                        <DialogContent className="sm:max-w-[500px] bg-white rounded-3xl">
                          <DialogHeader>
                            <DialogTitle className="text-2xl font-black text-gray-900" style={{ fontFamily: "'Inter', sans-serif" }}>
                              Reschedule Booking
                            </DialogTitle>
                            <DialogDescription className="text-gray-600 font-medium" style={{ fontFamily: "'Inter', sans-serif" }}>
                              Choose a new date and time for your lesson
                            </DialogDescription>
                          </DialogHeader>
                          <div className="grid gap-6 py-4">
                            <div className="grid gap-2">
                              <Label htmlFor="newDate" className="font-bold text-gray-900" style={{ fontFamily: "'Inter', sans-serif" }}>
                                New Date
                              </Label>
                              <Input
                                id="newDate"
                                type="date"
                                min={format(addDays(new Date(), 1), "yyyy-MM-dd")}
                                value={rescheduleData.newDate}
                                onChange={(e) => setRescheduleData({...rescheduleData, newDate: e.target.value})}
                                className="rounded-xl border-2 border-gray-300 focus:border-purple-500"
                                style={{ fontFamily: "'Inter', sans-serif" }}
                              />
                            </div>
                            <div className="grid gap-2">
                              <Label htmlFor="newTime" className="font-bold text-gray-900" style={{ fontFamily: "'Inter', sans-serif" }}>
                                New Time
                              </Label>
                              <Input
                                id="newTime"
                                type="time"
                                value={rescheduleData.newTime}
                                onChange={(e) => setRescheduleData({...rescheduleData, newTime: e.target.value})}
                                className="rounded-xl border-2 border-gray-300 focus:border-purple-500"
                                style={{ fontFamily: "'Inter', sans-serif" }}
                              />
                            </div>
                            <div className="grid gap-2">
                              <Label htmlFor="duration" className="font-bold text-gray-900" style={{ fontFamily: "'Inter', sans-serif" }}>
                                Duration (minutes)
                              </Label>
                              <select
                                id="duration"
                                value={rescheduleData.duration}
                                onChange={(e) => setRescheduleData({...rescheduleData, duration: Number(e.target.value)})}
                                className="flex h-10 w-full rounded-xl border-2 border-gray-300 bg-white px-3 py-2 text-sm focus:outline-none focus:border-purple-500"
                                style={{ fontFamily: "'Inter', sans-serif" }}
                              >
                                <option value={20}>20 minutes</option>
                                <option value={45}>45 minutes</option>
                                <option value={60}>60 minutes</option>
                                <option value={90}>90 minutes</option>
                              </select>
                            </div>
                            <div className="grid gap-2">
                              <Label htmlFor="reason" className="font-bold text-gray-900" style={{ fontFamily: "'Inter', sans-serif" }}>
                                Reason for Rescheduling
                              </Label>
                              <Textarea
                                id="reason"
                                placeholder="Please explain why you need to reschedule..."
                                value={rescheduleData.reason}
                                onChange={(e) => setRescheduleData({...rescheduleData, reason: e.target.value})}
                                className="rounded-xl border-2 border-gray-300 focus:border-purple-500 min-h-[100px]"
                                style={{ fontFamily: "'Inter', sans-serif" }}
                              />
                            </div>
                          </div>
                          <DialogFooter className="gap-2">
                            <Button
                              variant="outline"
                              onClick={() => setRescheduleOpen(false)}
                              className="border-2 border-gray-300 hover:border-gray-500 bg-white hover:bg-gray-50 text-gray-700 rounded-xl font-bold"
                              style={{ fontFamily: "'Inter', sans-serif" }}
                            >
                              Cancel
                            </Button>
                            <Button
                              onClick={handleReschedule}
                              disabled={processing}
                              className="bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 text-white rounded-xl font-bold"
                              style={{ fontFamily: "'Inter', sans-serif" }}
                            >
                              {processing ? "Rescheduling..." : "Confirm Reschedule"}
                            </Button>
                          </DialogFooter>
                        </DialogContent>
                      </Dialog>
                      <Button
                        onClick={handleCancel}
                        disabled={processing}
                        className="w-full md:w-auto bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white shadow-lg rounded-xl px-8 h-12 font-bold text-base transition-all duration-300"
                        style={{ fontFamily: "'Inter', sans-serif" }}
                      >
                        {processing ? "Cancelling..." : "Cancel Booking"}
                      </Button>
                    </>
                  )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
