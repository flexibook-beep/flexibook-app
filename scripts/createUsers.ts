import "dotenv/config";
import { prisma } from "../lib/prisma"; // adjust path if needed
import { hash } from "bcryptjs";

async function main() {
  const studentPassword = await hash("student123", 10);
  const teacherPassword = await hash("teacher123", 10);

  // Create a student
  const student = await prisma.user.create({
    data: {
      id: "student-1",
      email: "hillary@example.com",
      name: "Student One",
      password: studentPassword,
      role: "STUDENT",
      timezone: "UTC",
    },
  });

  // Create a teacher
  const teacherUser = await prisma.user.create({
    data: {
      id: "teacher-1",
      email: "okoth@example.com",
      name: "Teacher One",
      password: teacherPassword,
      role: "TEACHER",
      timezone: "UTC",
    },
  });

  await prisma.teacher.create({
    data: {
      id: "teacher-profile-1",
      userId: teacherUser.id,
      hourlyRate: 30,
      bufferTime: 10,
    },
  });

  console.log("Created student and teacher:", { student, teacherUser });
}

main()
  .catch(console.error)
  .finally(() => prisma.$disconnect());
