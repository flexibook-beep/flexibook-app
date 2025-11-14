"use client";

import { Button } from "@/components/ui/button";
import Link from "next/link";

export default function Home() {
  return (
    <div className="min-h-screen relative overflow-hidden">
      {/* Global background effects */}
      <div className="fixed inset-0 -z-10">
        {/* Floating geometric shapes */}
        <div className="absolute top-20 left-10 w-64 h-64 bg-gradient-to-br from-blue-100/40 to-indigo-100/40 rounded-full blur-3xl"></div>
        <div className="absolute top-40 right-20 w-80 h-80 bg-gradient-to-br from-purple-100/30 to-pink-100/30 rounded-full blur-3xl"></div>
        <div className="absolute bottom-20 left-1/4 w-72 h-72 bg-gradient-to-br from-cyan-100/30 to-blue-100/30 rounded-full blur-3xl"></div>
        <div className="absolute bottom-40 right-1/3 w-96 h-96 bg-gradient-to-br from-indigo-100/20 to-purple-100/20 rounded-full blur-3xl"></div>

        {/* Elegant lines */}
        <svg
          className="absolute top-0 left-0 w-full h-full opacity-20"
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            <linearGradient
              id="line-gradient"
              x1="0%"
              y1="0%"
              x2="100%"
              y2="100%"
            >
              <stop
                offset="0%"
                style={{ stopColor: "rgb(99, 102, 241)", stopOpacity: 0.1 }}
              />
              <stop
                offset="100%"
                style={{ stopColor: "rgb(168, 85, 247)", stopOpacity: 0.1 }}
              />
            </linearGradient>
          </defs>
          <line
            x1="0"
            y1="0"
            x2="100%"
            y2="50%"
            stroke="url(#line-gradient)"
            strokeWidth="1"
          />
          <line
            x1="100%"
            y1="0"
            x2="0"
            y2="50%"
            stroke="url(#line-gradient)"
            strokeWidth="1"
          />
        </svg>
      </div>

      <style jsx global>{`
        @import url("https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap");
      `}</style>
      {/* Navigation */}
      <nav className="bg-white/70 backdrop-blur-2xl border-b border-gray-200/60 sticky top-0 z-50 shadow-sm">
        <div className="container mx-auto px-8 py-4 flex justify-between items-center">
          <Link
            href="/"
            className="text-2xl font-black bg-gradient-to-r from-gray-900 via-gray-800 to-gray-900 bg-clip-text text-transparent tracking-tighter hover:from-gray-700 hover:via-gray-600 hover:to-gray-700 transition-all duration-300"
            style={{ fontFamily: "'Inter', sans-serif", fontWeight: 900 }}
          >
            Flexibook
          </Link>
          <div className="flex gap-4 items-center">
            <Link href="/auth/signin">
              <Button
                variant="ghost"
                className="text-gray-600 hover:text-gray-900 hover:bg-gray-100/80 font-semibold rounded-lg transition-all duration-300"
                style={{ fontFamily: "'Inter', sans-serif" }}
              >
                Sign In
              </Button>
            </Link>
            <Link href="/auth/signup">
              <Button
                className="bg-gradient-to-r from-gray-800 to-gray-900 hover:from-gray-900 hover:to-black text-white shadow-lg shadow-gray-400/20 hover:shadow-xl hover:shadow-gray-500/30 rounded-xl px-6 font-bold transition-all duration-300 hover:-translate-y-0.5"
                style={{ fontFamily: "'Inter', sans-serif", fontWeight: 700 }}
              >
                Get Started
              </Button>
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative py-32 px-8 overflow-hidden">
        <div className="container mx-auto max-w-5xl text-center relative z-10">
          {/* 3D Character Illustrations */}
          <div className="absolute -top-16 -left-64 w-[400px] h-[400px] opacity-50">
            <img
              src="https://illustrations.popsy.co/amber/online-shopping.svg"
              alt="3d character studying"
              className="w-full h-full object-contain filter drop-shadow-2xl"
            />
          </div>
          <div className="absolute -top-32 -right-48 w-[400px] h-[400px] opacity-50">
            <img
              src="https://illustrations.popsy.co/amber/man-riding-a-rocket.svg"
              alt="3d character learning"
              className="w-full h-full object-contain filter drop-shadow-2xl"
            />
          </div>

          <h1
            className="text-8xl font-black text-gray-900 mb-8 tracking-tighter leading-none text-shadow-soft"
            style={{ fontFamily: "'Inter', sans-serif", fontWeight: 900 }}
          >
            Book language lessons
            <br />
            <span className="bg-gradient-to-r from-blue-600 via-indigo-600 to-purple-600 bg-clip-text text-transparent">
              on your schedule
            </span>
          </h1>

          <p
            className="text-2xl text-gray-600 mb-14 leading-relaxed font-medium max-w-3xl mx-auto"
            style={{ fontFamily: "'Inter', sans-serif" }}
          >
            Connect with experienced teachers worldwide. Choose your time, pick
            your duration, and start learning today.
          </p>

          <div className="flex gap-5 justify-center mb-20">
            <Link href="/dashboard?role=student">
              {/*<Link href="/auth/signup?role=student">*/}
              <Button
                size="lg"
                className="bg-gradient-to-r from-gray-700 to-gray-800 hover:from-gray-800 hover:to-gray-900 text-white shadow-2xl shadow-gray-400/30 rounded-2xl px-12 h-16 text-lg font-bold hover:shadow-gray-500/40 hover:-translate-y-0.5 transition-all duration-300"
                style={{ fontFamily: "'Inter', sans-serif", fontWeight: 700 }}
              >
                Find a Teacher →
              </Button>
            </Link>

            <Link href="/dashboard?role=teacher">
              {/*<Link href="/auth/signup?role=teacher">*/}
              <Button
                size="lg"
                variant="outline"
                className="bg-white border-2 border-gray-300 text-gray-700 hover:bg-gray-50 hover:border-gray-500 rounded-2xl px-12 h-16 text-lg font-bold shadow-lg hover:shadow-xl hover:-translate-y-0.5 transition-all duration-300"
                style={{ fontFamily: "'Inter', sans-serif", fontWeight: 700 }}
              >
                Become a Teacher
              </Button>
            </Link>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-gray-200 py-12 px-8 bg-white">
        <div className="container mx-auto text-center">
          <div className="mb-4">
            <Link href="/" className="text-xl font-semibold text-gray-900">
              Flexibook
            </Link>
          </div>
          <p className="text-gray-500 text-sm">
            &copy; 2024 Flexibook. All rights reserved.
          </p>
        </div>
      </footer>
    </div>
  );
}
