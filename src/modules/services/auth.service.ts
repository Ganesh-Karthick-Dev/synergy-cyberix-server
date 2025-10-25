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
   * Create a new session for a user, invalidating all previous sessions
   * This ensures only one active session per user
   */
  async createSession(
    userId: string, 
    token: string, 
    deviceInfo?: string, 
    ipAddress?: string, 
    userAgent?: string
  ): Promise<void> {
    try {
      // Delete all existing sessions for this user to enforce single session
      await prisma.session.deleteMany({
        where: { userId }
      });

      // Create new session
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
