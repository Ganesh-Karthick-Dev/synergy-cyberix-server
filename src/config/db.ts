import { PrismaClient } from '@prisma/client';
import { config } from './env.config';

declare global {
  var __prisma: PrismaClient | undefined;
}

// Create a single instance of PrismaClient
const prisma = globalThis.__prisma || new PrismaClient({
  log: config.nodeEnv === 'development' ? ['query', 'error', 'warn'] : ['error'],
  errorFormat: 'pretty',
});

// In development, save the instance to global to prevent multiple instances
if (config.nodeEnv === 'development') {
  globalThis.__prisma = prisma;
}

// Graceful shutdown
process.on('beforeExit', async () => {
  await prisma.$disconnect();
});

process.on('SIGINT', async () => {
  await prisma.$disconnect();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  await prisma.$disconnect();
  process.exit(0);
});

export { prisma };
