import { AuthService } from '../modules/services/auth.service';

const authService = new AuthService();

/**
 * Cleanup job to remove expired login blocks and sessions
 * This should be called periodically (e.g., every 5 minutes)
 */
export async function runCleanupJobs(): Promise<void> {
  try {
    console.log('🧹 Running cleanup jobs...');
    
    // Clean up expired login blocks
    await authService.cleanupExpiredBlocks();
    
    // Clean up expired sessions
    await authService.cleanupExpiredSessions();
    
    console.log('✅ Cleanup jobs completed successfully');
  } catch (error) {
    console.error('❌ Cleanup jobs failed:', error);
  }
}

/**
 * Start the cleanup scheduler
 * Runs cleanup every 5 minutes
 */
export function startCleanupScheduler(): void {
  console.log('🕐 Starting cleanup scheduler (every 5 minutes)...');
  
  // Run cleanup immediately
  runCleanupJobs();
  
  // Schedule cleanup every 5 minutes
  setInterval(runCleanupJobs, 5 * 60 * 1000);
}
