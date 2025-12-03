"use client";

import { useSession, signOut } from "next-auth/react";
import Link from "next/link";
import { Button } from "./ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "./ui/dropdown-menu";
import { Avatar, AvatarFallback, AvatarImage } from "./ui/avatar";
import { Calendar, Home, User, LogOut, Sparkles, Menu, X } from "lucide-react";
import { useState } from "react";

export function Navbar() {
  const { data: session } = useSession();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  if (!session) return null;

  const initials =
    session.user?.name
      ?.split(" ")
      .map((n) => n[0])
      .join("")
      .toUpperCase() || "U";

  const links = [
    {
      href: "/dashboard",
      label: "Dashboard",
      icon: <Home className="w-4 h-4 mr-2" />,
    },
    ...(session.user.role === "STUDENT"
      ? [
          {
            href: "/teachers",
            label: "Find Teachers",
            icon: <User className="w-4 h-4 mr-2" />,
          },
        ]
      : []),
    {
      href: "/bookings",
      label: "My Bookings",
      icon: <Calendar className="w-4 h-4 mr-2" />,
    },
  ];

  return (
    <nav className="bg-gray-900/10 backdrop-blur-3xl border-b border-gray-400/20 sticky top-0 z-50 shadow-lg">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8 py-3 flex justify-between items-center">
        {/* Logo */}
        <Link href="/dashboard" className="flex items-center gap-3 group">
          <div className="relative">
            <Sparkles
              className="w-8 h-8 text-gray-900 group-hover:text-gray-700 transition-all duration-300"
              strokeWidth={2.5}
            />
            <div className="absolute inset-0 bg-gradient-to-br from-indigo-500/20 to-purple-500/20 blur-xl group-hover:blur-2xl transition-all duration-300"></div>
          </div>
          <span
            className="text-2xl sm:text-3xl lg:text-3xl font-black text-gray-900 tracking-tighter group-hover:text-gray-700 transition-all duration-300"
            style={{
              fontFamily:
                "'Inter', -apple-system, BlinkMacSystemFont, sans-serif",
              fontWeight: 900,
              letterSpacing: "-0.05em",
              textShadow: "0 2px 8px rgba(0,0,0,0.1)",
            }}
          >
            Flexibook
          </span>
        </Link>

        {/* Desktop Links */}
        <div className="hidden md:flex items-center gap-2">
          {links.map((link) => (
            <Link key={link.href} href={link.href}>
              <Button
                variant="ghost"
                className="text-gray-900 hover:text-gray-700 hover:bg-gray-900/10 font-bold rounded-lg px-4 h-10 transition-all duration-300"
                style={{ fontFamily: "'Inter', sans-serif", fontWeight: 700 }}
              >
                {link.icon}
                {link.label}
              </Button>
            </Link>
          ))}

          {/* Avatar Dropdown */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                className="relative h-10 w-10 rounded-full hover:bg-gray-900/10 transition-all duration-300"
              >
                <Avatar className="h-10 w-10 ring-2 ring-gray-300 hover:ring-gray-400 transition-all duration-300">
                  <AvatarImage src={session.user.image || undefined} />
                  <AvatarFallback
                    className="bg-gradient-to-br from-gray-800 to-gray-900 text-white font-black text-base"
                    style={{ fontFamily: "'Inter', sans-serif" }}
                  >
                    {initials}
                  </AvatarFallback>
                </Avatar>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent
              align="end"
              className="w-64 backdrop-blur-xl bg-white/95 border-2 border-gray-200 rounded-2xl p-2 shadow-2xl"
            >
              <div className="flex items-center justify-start gap-3 p-3 mb-2">
                <Avatar className="h-12 w-12 ring-2 ring-gray-200">
                  <AvatarImage src={session.user.image || undefined} />
                  <AvatarFallback
                    className="bg-gradient-to-br from-gray-800 to-gray-900 text-white font-black"
                    style={{ fontFamily: "'Inter', sans-serif" }}
                  >
                    {initials}
                  </AvatarFallback>
                </Avatar>
                <div className="flex flex-col space-y-0.5 leading-tight">
                  <p
                    className="font-black text-gray-900 text-base"
                    style={{ fontFamily: "'Inter', sans-serif" }}
                  >
                    {session.user.name}
                  </p>
                  <p
                    className="text-sm text-gray-600 font-medium"
                    style={{ fontFamily: "'Inter', sans-serif" }}
                  >
                    {session.user.email}
                  </p>
                  <p
                    className="text-xs text-gray-500 capitalize font-bold mt-1 px-2 py-0.5 bg-gray-100 rounded-full inline-block w-fit"
                    style={{ fontFamily: "'Inter', sans-serif" }}
                  >
                    {session.user.role?.toLowerCase()}
                  </p>
                </div>
              </div>
              <DropdownMenuSeparator className="bg-gray-200" />
              {session.user.role === "TEACHER" && (
                <>
                  <Link href="/teachers/profile">
                    <DropdownMenuItem
                      className="rounded-xl my-1 py-2.5 font-semibold text-gray-700 hover:bg-gray-100 cursor-pointer"
                      style={{ fontFamily: "'Inter', sans-serif" }}
                    >
                      Profile Settings
                    </DropdownMenuItem>
                  </Link>
                  <Link href="/teachers/availability">
                    <DropdownMenuItem
                      className="rounded-xl my-1 py-2.5 font-semibold text-gray-700 hover:bg-gray-100 cursor-pointer"
                      style={{ fontFamily: "'Inter', sans-serif" }}
                    >
                      Manage Availability
                    </DropdownMenuItem>
                  </Link>
                  <DropdownMenuSeparator className="bg-gray-200" />
                </>
              )}
              <DropdownMenuItem
                onClick={() => signOut({ callbackUrl: "/" })}
                className="rounded-xl my-1 py-2.5 font-bold text-red-600 hover:bg-red-50 cursor-pointer"
                style={{ fontFamily: "'Inter', sans-serif" }}
              >
                <LogOut className="w-4 h-4 mr-2" />
                Sign Out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>

        {/* Mobile Hamburger */}
        <div className="md:hidden flex items-center gap-2">
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="p-2 rounded-md hover:bg-gray-900/10 transition-all duration-300"
          >
            {mobileMenuOpen ? (
              <X className="w-6 h-6 text-gray-900" />
            ) : (
              <Menu className="w-6 h-6 text-gray-900" />
            )}
          </button>

          {/* Avatar Dropdown */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                className="relative h-10 w-10 rounded-full hover:bg-gray-900/10 transition-all duration-300"
              >
                <Avatar className="h-10 w-10 ring-2 ring-gray-300 hover:ring-gray-400 transition-all duration-300">
                  <AvatarImage src={session.user.image || undefined} />
                  <AvatarFallback
                    className="bg-gradient-to-br from-gray-800 to-gray-900 text-white font-black text-base"
                    style={{ fontFamily: "'Inter', sans-serif" }}
                  >
                    {initials}
                  </AvatarFallback>
                </Avatar>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent
              align="end"
              className="w-64 backdrop-blur-xl bg-white/95 border-2 border-gray-200 rounded-2xl p-2 shadow-2xl"
            >
              <div className="flex items-center justify-start gap-3 p-3 mb-2">
                <Avatar className="h-12 w-12 ring-2 ring-gray-200">
                  <AvatarImage src={session.user.image || undefined} />
                  <AvatarFallback
                    className="bg-gradient-to-br from-gray-800 to-gray-900 text-white font-black"
                    style={{ fontFamily: "'Inter', sans-serif" }}
                  >
                    {initials}
                  </AvatarFallback>
                </Avatar>
                <div className="flex flex-col space-y-0.5 leading-tight">
                  <p
                    className="font-black text-gray-900 text-base"
                    style={{ fontFamily: "'Inter', sans-serif" }}
                  >
                    {session.user.name}
                  </p>
                  <p
                    className="text-sm text-gray-600 font-medium"
                    style={{ fontFamily: "'Inter', sans-serif" }}
                  >
                    {session.user.email}
                  </p>
                  <p
                    className="text-xs text-gray-500 capitalize font-bold mt-1 px-2 py-0.5 bg-gray-100 rounded-full inline-block w-fit"
                    style={{ fontFamily: "'Inter', sans-serif" }}
                  >
                    {session.user.role?.toLowerCase()}
                  </p>
                </div>
              </div>
              <DropdownMenuSeparator className="bg-gray-200" />
              {session.user.role === "TEACHER" && (
                <>
                  <Link href="/teachers/profile">
                    <DropdownMenuItem
                      className="rounded-xl my-1 py-2.5 font-semibold text-gray-700 hover:bg-gray-100 cursor-pointer"
                      style={{ fontFamily: "'Inter', sans-serif" }}
                    >
                      Profile Settings
                    </DropdownMenuItem>
                  </Link>
                  <Link href="/teachers/availability">
                    <DropdownMenuItem
                      className="rounded-xl my-1 py-2.5 font-semibold text-gray-700 hover:bg-gray-100 cursor-pointer"
                      style={{ fontFamily: "'Inter', sans-serif" }}
                    >
                      Manage Availability
                    </DropdownMenuItem>
                  </Link>
                  <DropdownMenuSeparator className="bg-gray-200" />
                </>
              )}
              <DropdownMenuItem
                onClick={() => signOut({ callbackUrl: "/" })}
                className="rounded-xl my-1 py-2.5 font-bold text-red-600 hover:bg-red-50 cursor-pointer"
                style={{ fontFamily: "'Inter', sans-serif" }}
              >
                <LogOut className="w-4 h-4 mr-2" />
                Sign Out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      {/* Mobile Menu */}
      {mobileMenuOpen && (
        <div className="md:hidden bg-white/95 backdrop-blur-xl border-t border-gray-200 shadow-lg w-full absolute left-0 top-full z-40">
          <div className="flex flex-col gap-2 p-4">
            {links.map((link) => (
              <Link key={link.href} href={link.href}>
                <Button
                  variant="ghost"
                  className="w-full justify-start text-gray-900 font-bold px-4 py-3 rounded-lg hover:bg-gray-100 transition-all duration-300"
                  style={{ fontFamily: "'Inter', sans-serif", fontWeight: 700 }}
                >
                  {link.icon}
                  {link.label}
                </Button>
              </Link>
            ))}
          </div>
        </div>
      )}
    </nav>
  );
}
