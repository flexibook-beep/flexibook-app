import { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import GoogleProvider from "next-auth/providers/google";
import { PrismaAdapter } from "@next-auth/prisma-adapter";
import bcrypt from "bcryptjs";
import { prisma } from "./prisma";

export const authOptions: NextAuthOptions = {
  adapter: PrismaAdapter(prisma),
  session: {
    strategy: "jwt",
  },
  pages: {
    signIn: "/auth/signin",
    //signUp: "/auth/signup",
  },
  providers: [
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      /** This setting allows NextAuth.js to automatically link a Google account
      * to an existing user account if they share the same email address.
      *
      * Rationale: This provides a smoother user experience, allowing users who
      * initially signed up with email*password to later sign in with Google
      * using the same email without encountering an "OAuthAccountNotLinked" error.
      *
      * Security Consideration: The "danger" in `allowDangerousEmailAccountLinking`
      * refers to the risk that if an attacker gains control of a user's Google
      * account, they could potentially gain access to the user's Flexibook account
      * without needing the Flexibook password. This relies on the security of
      * the Google account itself. Many large applications accept this trade-off
      * for improved UX, as Google accounts typically have strong security measures
      * (e.g., 2FA).
      */
      allowDangerousEmailAccountLinking: true,
    }),
    CredentialsProvider({
      name: "credentials",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) {
          throw new Error("Invalid credentials");
        }

        const user = await prisma.user.findUnique({
          where: {
            email: credentials.email,
          },
        });

        if (!user || !user.password) {
          throw new Error("Invalid credentials");
        }

        const isValid = await bcrypt.compare(
          credentials.password,
          user.password
        );

        if (!isValid) {
          throw new Error("Invalid credentials");
        }

        // Returning the full user object here is a good practice.
        // It keeps things simple, makes future changes to the User model easier to handle,
        // and helps with type safety throughout the application.
        return user;
      },
    }),
  ],
  callbacks: {
    async signIn({ user, account, profile }) {
      // This callback is super useful for controlling who can sign in and where they go afterwards.
      // For example, we can check if a user is allowed to sign in, or redirect them based on their role.
      if (account?.provider === "credentials") {
        // If it's a credentials sign-in, we just let it proceed.
        // The authorization logic already handled the validation.
        return true;
      }
      if (account?.provider === "google") {
        // For Google sign-ins, we need to check if the user already exists in our database.
        const userExists = await prisma.user.findUnique({
          where: { email: user.email! },
        });
        // If the user exists, great, just let them sign in.
        if (userExists) {
          // If the user exists but doesn't have a role, we'll send them to the role selection page.
          // This can happen if they signed up with Google before we added the role selection.
          if (!userExists.role) {
            return "/auth/select-role";
          }
          return true;
        }
        // If it's a new Google user, we'll create an account for them.
        // We won't assign a role here, so they'll be redirected to the role selection page.
        await prisma.user.create({
          data: {
            email: user.email!,
            name: user.name!,
            image: user.image!,
          },
        });
        return "/auth/select-role";
      }
      // If for some reason we get here, it means the sign-in wasn't handled, so we deny it.
      return false;
    },
    async jwt({ token, user, trigger, session }) {
      if (user) {
        token.id = user.id;
        token.role = user.role;
      }

      if (trigger === "update" && session) {
        return { ...token, ...session.user };
      }

      return token;
    },
    async session({ session, token }) {
      if (session.user) {
        session.user.id = token.id as string;
        session.user.role = token.role as string;
      }
      return session;
    },
  },
};
