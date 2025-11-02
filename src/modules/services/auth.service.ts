import jwt from 'jsonwebtoken';
import { config } from '../../config/env.config';
import { UserPayload } from '../../types';
import { CustomError } from '../../middlewares/error.middleware';
import { Service } from '../../decorators/service.decorator';
import { prisma } from '../../config/db';

export interface TokenPayload {
  userId: string;
  email: string;
  role: string;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
}

@Service()
export class AuthService {
  generateAccessToken(payload: TokenPayload): string {
    return jwt.sign(payload, config.jwt.secret, {
      expiresIn: config.jwt.expiresIn,
      issuer: 'cyberix-server',
      audience: 'cyberix-client'
    } as jwt.SignOptions);
  }

  generateRefreshToken(payload: TokenPayload): string {
    return jwt.sign(payload, config.jwt.refreshSecret, {
      expiresIn: config.jwt.refreshExpiresIn,
      issuer: 'cyberix-server',
      audience: 'cyberix-client'
    } as jwt.SignOptions);
  }

  generateTokens(user: UserPayload): AuthTokens {
    const payload: TokenPayload = {
      userId: user.id,
      email: user.email,
      role: user.role
    };

    return {
      accessToken: this.generateAccessToken(payload),
      refreshToken: this.generateRefreshToken(payload)
    };
  }

  verifyAccessToken(token: string): TokenPayload {
    try {
      return jwt.verify(token, config.jwt.secret, {
        issuer: 'cyberix-server',
        audience: 'cyberix-client'
      }) as TokenPayload;
    } catch (error) {
      throw new CustomError('Invalid or expired token', 401);
    }
  }

  verifyRefreshToken(token: string): TokenPayload {
    try {
      return jwt.verify(token, config.jwt.refreshSecret, {
        issuer: 'cyberix-server',
        audience: 'cyberix-client'
      }) as TokenPayload;
    } catch (error) {
      throw new CustomError('Invalid or expired refresh token', 401);
    }
  }

  async refreshTokens(refreshToken: string): Promise<AuthTokens> {
    const payload = this.verifyRefreshToken(refreshToken);
    
    // In a real application, you would verify the refresh token exists in the database
    // and is not expired/revoked
    
    return this.generateTokens({
      id: payload.userId,
      email: payload.email,
      role: payload.role,
      isActive: true
    });
  }

  extractTokenFromHeader(authHeader: string | undefined): string {
    if (!authHeader) {
      throw new CustomError('Authorization header is required', 401);
    }

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      throw new CustomError('Invalid authorization header format', 401);
    }

    const token = parts[1];
    if (!token) {
      throw new CustomError('Token is missing from authorization header', 401);
    }

    return token;
  }

  /**
   * Create a new session for a user (multiple devices allowed)
   */
  async createSession(
    userId: string, 
    token: string, 
    deviceInfo?: string, 
    ipAddress?: string, 
    userAgent?: string
  ): Promise<void> {
    try {
      // Create new session (multiple sessions allowed)
      await prisma.session.create({
        data: {
          userId,
          token,
          deviceInfo,
          ipAddress,
          userAgent,
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
        }
      });
    } catch (error) {
      throw new CustomError('Failed to create session', 500);
    }
  }

  /**
   * Validate if a session exists and is not expired
   */
  async validateSession(token: string): Promise<boolean> {
    try {
      const session = await prisma.session.findFirst({
        where: {
          token,
          expiresAt: { gt: new Date() }
        }
      });
      return !!session;
    } catch (error) {
      return false;
    }
  }

  /**
   * Invalidate a specific session by token
   */
  async invalidateSession(token: string): Promise<void> {
    try {
      await prisma.session.deleteMany({
        where: { token }
      });
    } catch (error) {
      throw new CustomError('Failed to invalidate session', 500);
    }
  }

  /**
   * Invalidate all sessions for a specific user
   */
  async invalidateAllUserSessions(userId: string): Promise<void> {
    try {
      await prisma.session.deleteMany({
        where: { userId }
      });
    } catch (error) {
      throw new CustomError('Failed to invalidate user sessions', 500);
    }
  }

  /**
   * Get active sessions for a user (for device management)
   */
  async getUserSessions(userId: string): Promise<any[]> {
    try {
      return await prisma.session.findMany({
        where: {
          userId,
          expiresAt: { gt: new Date() }
        },
        select: {
          id: true,
          deviceInfo: true,
          ipAddress: true,
          userAgent: true,
          createdAt: true,
          expiresAt: true
        }
      });
    } catch (error) {
      throw new CustomError('Failed to get user sessions', 500);
    }
  }

  /**
   * Force logout user from all devices (for admin use)
   */
  async forceLogoutUser(userId: string, adminUserId: string, reason: string): Promise<void> {
    try {
      // Get current sessions before invalidating
      const currentSessions = await this.getUserSessions(userId);
      
      // Invalidate all sessions
      await this.invalidateAllUserSessions(userId);
      
      // Log the forced logout
      await this.logLoginAttempt(
        userId,
        '', // Email will be fetched if needed
        true,
        undefined,
        undefined,
        `Forced logout by admin ${adminUserId}: ${reason}. Previous sessions: ${currentSessions.length}`
      );
    } catch (error) {
      throw new CustomError('Failed to force logout user', 500);
    }
  }

  /**
   * Check if user is blocked due to failed login attempts
   */
  async isUserBlocked(email: string): Promise<{
    isBlocked: boolean;
    attempts: number;
    blockedAt: Date | null;
    expiresAt: Date | null;
    remainingMinutes: number;
  }> {
    try {
      const block = await prisma.loginBlock.findUnique({
        where: { email }
      });

      if (!block || !block.isActive) {
        return {
          isBlocked: false,
          attempts: 0,
          blockedAt: null,
          expiresAt: null,
          remainingMinutes: 0
        };
      }

      // Check if block has expired
      if (new Date() > block.expiresAt) {
        // Remove expired block
        await prisma.loginBlock.delete({
          where: { id: block.id }
        });

        return {
          isBlocked: false,
          attempts: 0,
          blockedAt: null,
          expiresAt: null,
          remainingMinutes: 0
        };
      }

      // Calculate remaining minutes
      const remainingMs = block.expiresAt.getTime() - new Date().getTime();
      const remainingMinutes = Math.ceil(remainingMs / (1000 * 60));

      return {
        isBlocked: true,
        attempts: block.attempts,
        blockedAt: block.blockedAt,
        expiresAt: block.expiresAt,
        remainingMinutes: Math.max(0, remainingMinutes)
      };
    } catch (error) {
      throw new CustomError('Failed to check user block status', 500);
    }
  }

  /**
   * Record failed login attempt and handle blocking
   */
  async recordFailedLoginAttempt(
    email: string,
    ipAddress?: string,
    userAgent?: string,
    reason?: string
  ): Promise<{
    isBlocked: boolean;
    attempts: number;
    remainingMinutes: number;
  }> {
    try {
      const MAX_ATTEMPTS = 3;
      const BLOCK_DURATION_MINUTES = 5;

      // Check if user is already blocked
      const currentBlock = await this.isUserBlocked(email);
      if (currentBlock.isBlocked) {
        return {
          isBlocked: true,
          attempts: currentBlock.attempts,
          remainingMinutes: currentBlock.remainingMinutes
        };
      }

      // Get or create login block record
      const existingBlock = await prisma.loginBlock.findUnique({
        where: { email }
      });

      if (existingBlock) {
        // Update existing block
        const newAttempts = existingBlock.attempts + 1;
        const isBlocked = newAttempts >= MAX_ATTEMPTS;
        
        const updatedBlock = await prisma.loginBlock.update({
          where: { id: existingBlock.id },
          data: {
            attempts: newAttempts,
            isActive: isBlocked,
            blockedAt: isBlocked ? new Date() : existingBlock.blockedAt,
            expiresAt: isBlocked ? new Date(Date.now() + BLOCK_DURATION_MINUTES * 60 * 1000) : existingBlock.expiresAt,
            ipAddress: ipAddress || existingBlock.ipAddress
          }
        });

        if (isBlocked) {
          // Log the blocking event
          await this.logLoginAttempt(
            '', // No userId for failed attempts
            email,
            false,
            ipAddress,
            userAgent,
            `Account blocked after ${MAX_ATTEMPTS} failed attempts. Blocked until ${updatedBlock.expiresAt.toISOString()}`
          );

          // Send suspicious activity email to user (only in production mode)
          if (process.env.EMAIL_NOTIFICATIONS === 'true' || process.env.APP_MODE === 'production') {
            try {
              const { EmailService } = await import('./email.service');
              const emailService = new EmailService();
              
              await emailService.sendSuspiciousActivityAlert(email, {
                type: 'ACCOUNT_BLOCKED',
                attempts: newAttempts,
                ipAddress,
                userAgent,
                blockedAt: updatedBlock.blockedAt,
                expiresAt: updatedBlock.expiresAt,
                remainingMinutes: BLOCK_DURATION_MINUTES
              });

              // Send admin notification
              await emailService.sendAdminSecurityAlert('webnox@admin.com', {
                type: 'ACCOUNT_BLOCKED',
                userEmail: email,
                attempts: newAttempts,
                ipAddress,
                userAgent,
                timestamp: new Date()
              });
            } catch (emailError) {
              console.error('Failed to send suspicious activity emails:', emailError);
              // Don't throw error to avoid breaking the login flow
            }
          }
        }

        return {
          isBlocked,
          attempts: newAttempts,
          remainingMinutes: isBlocked ? BLOCK_DURATION_MINUTES : 0
        };
      } else {
        // Create new block record
        const newAttempts = 1;
        const isBlocked = newAttempts >= MAX_ATTEMPTS;
        
        const newBlock = await prisma.loginBlock.create({
          data: {
            email,
            attempts: newAttempts,
            isActive: isBlocked,
            blockedAt: isBlocked ? new Date() : new Date(),
            expiresAt: isBlocked ? new Date(Date.now() + BLOCK_DURATION_MINUTES * 60 * 1000) : new Date(),
            ipAddress
          }
        });

        return {
          isBlocked,
          attempts: newAttempts,
          remainingMinutes: isBlocked ? BLOCK_DURATION_MINUTES : 0
        };
      }
    } catch (error) {
      throw new CustomError('Failed to record failed login attempt', 500);
    }
  }

  /**
   * Clear login block for successful login
   */
  async clearLoginBlock(email: string): Promise<void> {
    try {
      await prisma.loginBlock.deleteMany({
        where: { email }
      });
    } catch (error) {
      // Don't throw error for cleanup failures
      console.error('Failed to clear login block:', error);
    }
  }

  /**
   * Clean up expired login blocks
   */
  async cleanupExpiredBlocks(): Promise<void> {
    try {
      const result = await prisma.loginBlock.deleteMany({
        where: {
          OR: [
            { expiresAt: { lt: new Date() } },
            { isActive: false }
          ]
        }
      });
      
      if (result.count > 0) {
        console.log(`Cleaned up ${result.count} expired login blocks`);
      }
    } catch (error) {
      console.error('Failed to cleanup expired blocks:', error);
    }
  }

  /**
   * Clean up expired sessions (can be called periodically)
   */
  async cleanupExpiredSessions(): Promise<void> {
    try {
      await prisma.session.deleteMany({
        where: {
          expiresAt: { lt: new Date() }
        }
      });
    } catch (error) {
      throw new CustomError('Failed to cleanup expired sessions', 500);
    }
  }

  /**
   * Log login attempt to the database
   */
  async logLoginAttempt(
    userId: string,
    email: string,
    success: boolean,
    ipAddress?: string,
    userAgent?: string,
    reason?: string
  ): Promise<void> {
    try {
      await prisma.loginLog.create({
        data: {
          userId,
          email,
          success,
          ipAddress,
          userAgent,
          reason
        }
      });
    } catch (error) {
      // Don't throw error for logging failures, just log to console
      console.error('Failed to log login attempt:', error);
    }
  }
}
