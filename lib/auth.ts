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
          return true;
        }
        // If it's a new Google user, we'll create an account for them.
        // By default, they'll get the 'STUDENT' role as defined in our schema.
        await prisma.user.create({
          data: {
            email: user.email!,
            name: user.name!,
            image: user.image!,
          },
        });
        return true;
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
