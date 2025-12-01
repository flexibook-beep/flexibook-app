module.exports = {
  testEnvironment: 'node',
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/$1',
  },
  transform: {
    '^.+\\.ts$': ['@swc/jest'],
  },
  testMatch: [
    '**/__tests__/**/*.test.ts'
  ],
};
