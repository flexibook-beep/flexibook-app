"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Navbar } from "@/components/navbar";
import { Button } from "@/components/ui/button";
import { format } from "date-fns";
import { formatCurrency, formatDuration } from "@/lib/utils";
import { Calendar, Clock } from "lucide-react";

const STATUS_CONFIG: Record<
  string,
  { bg: string; text: string; label: string }
> = {
  PENDING_PAYMENT: {
    bg: "bg-yellow-100",
    text: "text-yellow-800",
    label: "Pending Payment",
  },
  CONFIRMED: { bg: "bg-green-100", text: "text-green-800", label: "Confirmed" },
  COMPLETED: { bg: "bg-blue-100", text: "text-blue-800", label: "Completed" },
  CANCELLED: { bg: "bg-red-100", text: "text-red-800", label: "Cancelled" },
  REFUNDED: { bg: "bg-gray-100", text: "text-gray-800", label: "Refunded" },
};

export default function BookingsPage() {
  const [bookings, setBookings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<string>("all");

  useEffect(() => {
    fetchBookings();
  }, [filter]);

  const fetchBookings = async () => {
    try {
      const url =
        filter === "all" ? "/api/bookings" : `/api/bookings?status=${filter}`;
      const response = await fetch(url);
      const data = await response.json();
      setBookings(data.bookings || []);
    } catch (error) {
      console.error("Failed to fetch bookings:", error);
    } finally {
      setLoading(false);
    }
  };

  const filters = [
    { label: "All", value: "all" },
    { label: "Pending Payment", value: "PENDING_PAYMENT" },
    { label: "Confirmed", value: "CONFIRMED" },
    { label: "Completed", value: "COMPLETED" },
    { label: "Cancelled", value: "CANCELLED" },
  ];

  return (
    <div className="min-h-screen relative">
      <Navbar />
      {/* Full Screen Abstract Background */}
      <div className="fixed inset-0 -z-10 pointer-events-none">
        <div
          className="absolute inset-0"
          style={{
            background: `
            radial-gradient(circle at 40% 40%, rgba(34, 211, 238, 0.12) 0%, transparent 50%),
            radial-gradient(circle at 90% 10%, rgba(99, 102, 241, 0.15) 0%, transparent 50%),
            radial-gradient(circle at 10% 90%, rgba(168, 85, 247, 0.1) 0%, transparent 50%),
            linear-gradient(135deg, rgba(250, 251, 252, 0.8) 0%, rgba(255, 255, 255, 0.9) 100%)
          `,
          }}
        ></div>
        <div
          className="absolute inset-0"
          style={{
            backgroundImage: `
            repeating-linear-gradient(30deg, transparent, transparent 90px, rgba(34, 211, 238, 0.02) 90px, rgba(34, 211, 238, 0.02) 180px),
            repeating-linear-gradient(150deg, transparent, transparent 90px, rgba(99, 102, 241, 0.02) 90px, rgba(99, 102, 241, 0.02) 180px)
          `,
          }}
        ></div>
      </div>
      <div className="container mx-auto px-8 py-12 max-w-6xl">
        <div className="mb-12">
          <h1
            className="text-5xl font-black text-gray-900 tracking-tight mb-6"
            style={{ fontFamily: "'Inter', sans-serif" }}
          >
            My Bookings
          </h1>

          <div className="flex gap-3 flex-wrap">
            {filters.map((f) => (
              <Button
                key={f.value}
                variant={filter === f.value ? "default" : "outline"}
                onClick={() => setFilter(f.value)}
                className={
                  filter === f.value
                    ? "bg-gradient-to-r from-gray-800 to-gray-900 hover:from-gray-900 hover:to-black text-white rounded-xl px-6 h-10 font-bold transition-all duration-300"
                    : "border-2 border-gray-300 hover:border-gray-500 bg-white hover:bg-gray-50 text-gray-700 rounded-xl px-6 h-10 font-semibold transition-all duration-300"
                }
                style={{ fontFamily: "'Inter', sans-serif" }}
              >
                {f.label}
              </Button>
            ))}
          </div>
        </div>

        {loading ? (
          <div className="text-center py-20">
            <p
              className="text-gray-500 text-lg"
              style={{ fontFamily: "'Inter', sans-serif" }}
            >
              Loading bookings...
            </p>
          </div>
        ) : bookings.length === 0 ? (
          <div className="text-center py-20">
            <p
              className="text-gray-500 text-lg mb-8"
              style={{ fontFamily: "'Inter', sans-serif" }}
            >
              No bookings found
            </p>
            <Link href="/teachers">
              <Button
                className="bg-gradient-to-r from-gray-800 to-gray-900 hover:from-gray-900 hover:to-black text-white shadow-lg rounded-xl px-10 h-12 font-bold text-base transition-all duration-300"
                style={{ fontFamily: "'Inter', sans-serif" }}
              >
                Find a Teacher
              </Button>
            </Link>
          </div>
        ) : (
          <div className="space-y-5">
            {bookings.map((booking) => {
              const status =
                STATUS_CONFIG[booking.status] || STATUS_CONFIG.PENDING_PAYMENT;
              return (
                <div
                  key={booking.id}
                  className="backdrop-blur-xl bg-white/80 rounded-3xl shadow-lg border border-gray-200/60 p-8 hover:shadow-2xl transition-all duration-300"
                >
                  <div className="flex items-start justify-between mb-6">
                    <div className="flex items-center gap-4">
                      <h3
                        className="text-2xl font-black text-gray-900"
                        style={{ fontFamily: "'Inter', sans-serif" }}
                      >
                        {booking.teacher.name}
                      </h3>
                      <span
                        className={`${status.bg} ${status.text} px-4 py-1.5 rounded-full text-xs font-bold`}
                        style={{ fontFamily: "'Inter', sans-serif" }}
                      >
                        {status.label}
                      </span>
                    </div>
                    <div className="text-right">
                      <div
                        className="text-3xl font-black text-gray-900"
                        style={{ fontFamily: "'Inter', sans-serif" }}
                      >
                        {formatCurrency(booking.payment?.amount || 0)}
                      </div>
                    </div>
                  </div>

                  <div className="flex flex-col md:flex-row gap-6 justify-between items-start md:items-end">
                    <div className="space-y-3 flex-1">
                      <div
                        className="flex items-center gap-3 text-base text-gray-700"
                        style={{ fontFamily: "'Inter', sans-serif" }}
                      >
                        <Calendar className="w-5 h-5 text-gray-600" />
                        <span className="font-semibold">
                          {format(new Date(booking.startTime), "PPP")}
                        </span>
                      </div>
                      <div
                        className="flex items-center gap-3 text-base text-gray-700"
                        style={{ fontFamily: "'Inter', sans-serif" }}
                      >
                        <Clock className="w-5 h-5 text-gray-600" />
                        <span className="font-semibold">
                          {format(new Date(booking.startTime), "p")} •{" "}
                          {formatDuration(booking.durationMinutes)}
                        </span>
                      </div>
                      {booking.notes && (
                        <p
                          className="text-sm text-gray-600 mt-3 pl-8 font-medium"
                          style={{ fontFamily: "'Inter', sans-serif" }}
                        >
                          <span className="font-bold">Notes:</span>{" "}
                          {booking.notes}
                        </p>
                      )}
                    </div>

                    <div className="flex items-end">
                      <Link href={`/bookings/${booking.id}`}>
                        <Button
                          className="border-2 border-gray-300 hover:border-gray-500 bg-white hover:bg-gray-50 text-gray-700 rounded-xl px-8 h-11 font-bold text-base transition-all duration-300"
                          style={{ fontFamily: "'Inter', sans-serif" }}
                        >
                          View Details
                        </Button>
                      </Link>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
