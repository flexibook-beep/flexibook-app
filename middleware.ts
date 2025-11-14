// middleware.ts

// Once auth is implemented, uncomment the following line
// export { default } from "next-auth/middleware";

// Once auth is implemented, also uncomment the following:
/*
export const config = {
  matcher: [
    "/dashboard/:path*",
    "/bookings/:path*",
    "/teachers/profile/:path*",
  ],
};
*/

// Just let everything through for now until Samuel implements Auth.
// Only for checking that the dashboard is displaying correctly.

import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

export function middleware(req: NextRequest) {
  return NextResponse.next();
}

export const config = {
  matcher: [
    "/dashboard/:path*",
    "/bookings/:path*",
    "/teachers/profile/:path*",
  ],
};
