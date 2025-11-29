// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { withAuth } from 'next-auth/middleware';

// The `withAuth` middleware augments the request with the user's token.
export default withAuth(
  function middleware(req: NextRequest) {
    const pathname = req.nextUrl.pathname;
    // The token is available on the request because the `authorized` is executed.
    const token = (req as any).nextauth.token;

    // Redirect students trying to access teacher routes.
    if (pathname.startsWith('/teachers/profile/') && token?.role === 'STUDENT') {
      return NextResponse.redirect(new URL('/dashboard', req.url));
    }

    // Allow the request to proceed if no redirect is needed.
    return NextResponse.next();
  },
  {
    callbacks: {
      /**
       * This callback decides if the user is authorized to access a page.
       * If it returns `false`, the user is redirected to the sign-in page.
       * If it returns `true`, the middleware function is executed.
       */
      authorized: ({ token }) => {
        // `!!token` converts the token (or null) to a boolean.
        // If a token exists, the user is considered authenticated.
        return !!token;
      },
    },
    pages: {
      // Specifies the sign-in page for unauthenticated users.
      signIn: '/auth/signin',
    },
  }
);

// The middleware to run on specific paths.
export const config = {
  matcher: [
    '/dashboard',
    '/bookings/:path*',
    '/teachers/:path*',
  ],
};