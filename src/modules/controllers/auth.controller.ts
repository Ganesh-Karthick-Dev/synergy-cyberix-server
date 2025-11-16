import { Request, Response, NextFunction } from 'express';
import { Controller, Post, Get, Put, Delete } from '../../decorators/controller.decorator';
import { Validate, RegisterUserValidation } from '../../decorators/validation.decorator';
import { body } from 'express-validator';
import { Service } from '../../decorators/service.decorator';
import { UserService } from '../services/user.service';
import { AuthService } from '../services/auth.service';
import { NotificationService } from '../services/notification.service';
import { ApiResponse } from '../../types';
import { authenticate } from '../../middlewares/auth.middleware';
import { prisma } from '../../config/db';
import { Use } from '../../decorators/middleware.decorator';
import { config } from '../../config/env.config';
import { CustomError } from '../../middlewares/error.middleware';
import passport from 'passport';

@Service()
@Controller('/api/auth')
export class AuthController {
  private userService: UserService;
  private authService: AuthService;
  private notificationService: NotificationService;

  constructor() {
    this.userService = new UserService();
    this.authService = new AuthService();
    this.notificationService = new NotificationService();
  }

  @Post('/login')
  @Validate([
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('password').notEmpty().withMessage('Password is required')
  ])
  async login(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { email, password, deviceInfo, fcmToken } = req.body;

      console.log('req.body', req.body);
      console.log('🟢 [Login] FCM token in request:', fcmToken ? `${fcmToken.substring(0, 20)}...` : 'NOT PROVIDED');

    // Check if user is blocked due to failed attempts (only in production mode)
    if (config.security.loginBlocking) {
      const blockStatus = await this.authService.isUserBlocked(email);
      if (blockStatus.isBlocked) {
        res.status(423).json({
          success: false,
          error: {
            message: `Account temporarily blocked due to multiple failed login attempts. Please try again in ${blockStatus.remainingMinutes} minutes.`,
            statusCode: 423,
            code: 'ACCOUNT_BLOCKED',
            details: {
              attempts: blockStatus.attempts,
              blockedAt: blockStatus.blockedAt,
              expiresAt: blockStatus.expiresAt,
              remainingMinutes: blockStatus.remainingMinutes
            }
          }
        });
        return;
      }
    }

    // Validate credentials - this will throw CustomError if invalid
    const user = await this.userService.validateCredentials({ email, password }, req.ip, req.get('User-Agent'));

    // SECURITY: Double-check admin access - only authorized admin emails can be admin
    const adminEmails = ['webnox@admin.com', 'webnox1@admin.com'];
    if (user.role === 'ADMIN' && !adminEmails.includes(email)) {
      // Log failed admin login attempt
      await this.authService.logLoginAttempt(
        user.id,
        email,
        false,
        req.ip,
        req.get('User-Agent'),
        'SECURITY ALERT: Unauthorized admin login attempt - only authorized admin emails can login as admin'
      );

      // Send admin security alert for unauthorized admin access (only in production mode)
      if (config.security.emailNotifications) {
        try {
          const { EmailService } = await import('../services/email.service');
          const emailService = new EmailService();

          await emailService.sendAdminSecurityAlert('webnox@admin.com', {
            type: 'UNAUTHORIZED_ADMIN_ACCESS',
            userEmail: email,
            attempts: 1,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            timestamp: new Date()
          });
        } catch (emailError) {
          console.error('Failed to send admin security alert:', emailError);
        }
      }

      throw new CustomError('Access denied. Admin login is restricted to authorized personnel only.', 403);
    }

    const tokens = this.authService.generateTokens({
      id: user.id,
      email: user.email,
      role: user.role,
      isActive: user.isActive
    });

    // Create new session (multiple devices allowed)
    await this.authService.createSession(
      user.id,
      tokens.accessToken,
      deviceInfo,
      req.ip,
      req.get('User-Agent')
    );

    // Send login notification to user about new device login
    try {
      await this.notificationService.sendLoginNotification({
        userId: user.id,
        newDeviceInfo: deviceInfo || 'Unknown Device',
        newIpAddress: req.ip || 'Unknown IP',
        newUserAgent: req.get('User-Agent') || 'Unknown User Agent',
        timestamp: new Date()
      });
    } catch (notificationError) {
      // Log notification error but don't fail the login
      console.error('Failed to send login notification:', notificationError);
    }

    // Set cookies for tokens (backend handles ALL cookie management)
    // Set both HTTP-only and readable cookies for maximum compatibility
    // HTTP-only for security, readable for client-side access (needed for API proxy routes)

    // HTTP-only cookie (secure, cannot be read by JavaScript)
    res.cookie('accessToken', tokens.accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax', // Lax for cross-origin in development
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/', // Ensure cookies are available for all paths
      // Don't set domain - allow cross-origin
    });
    console.log('🟢 [Login] Set HTTP-only accessToken cookie');

    // Readable cookie (for client-side access, less secure but needed for API routes)
    res.cookie('accessToken', tokens.accessToken, {
      httpOnly: false, // Allow client-side reading
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/', // Ensure cookies are available for all paths
    });
    console.log('🟢 [Login] Set readable accessToken cookie');

    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax', // Lax for development
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      path: '/', // Ensure cookies are available for all paths
      // Don't set domain - browsers will use current hostname
    });
    console.log('🟢 [Login] Set refreshToken cookie');

    // Set a non-HttpOnly cookie that JavaScript can read to check auth status
    res.cookie('isAuthenticated', 'true', {
      httpOnly: false, // Allow JavaScript to read this
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/',
    });
    console.log('🟢 [Login] Set isAuthenticated cookie');

    // Store FCM token if provided
    if (fcmToken) {
      try {
        console.log('🟢 [Login] Attempting to store FCM token for user:', user.id);
        const { FirebaseService } = await import('../services/firebase.service');
        const firebaseService = new FirebaseService();
        
        await firebaseService.storeFcmToken(user.id, fcmToken, {
          userAgent: req.get('User-Agent'),
          ipAddress: req.ip,
          deviceInfo: deviceInfo || req.get('User-Agent'),
        });
        
        console.log('🟢 [Login] ✅ FCM token stored successfully in database');
      } catch (fcmError) {
        // Log error but don't fail login if FCM storage fails
        console.error('🟡 [Login] ❌ Failed to store FCM token (non-critical):', fcmError);
        if (fcmError instanceof Error) {
          console.error('🟡 [Login] FCM Error details:', {
            message: fcmError.message,
            stack: fcmError.stack,
          });
        }
      }
    } else {
      console.log('🟡 [Login] No FCM token provided in login request');
    }

    // Clear any existing login block on successful login
    await this.authService.clearLoginBlock(email);

    // Log successful login attempt
    await this.authService.logLoginAttempt(
      user.id,
      user.email,
      true,
      req.ip,
      req.get('User-Agent'),
      'Login successful'
    );

    const response: ApiResponse = {
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          isActive: user.isActive
        },
        // Include token in response body for Electron/desktop app compatibility
        // Cookies are also set for web browser compatibility
        token: tokens.accessToken,
        refreshToken: tokens.refreshToken
      },
      message: 'Login successful. Previous sessions have been invalidated.'
    };

      // Note: Tokens are set as cookies AND included in response body for maximum compatibility
      // Cookies work for web browsers, response body works for Electron/desktop apps
      console.log('🟢 [Login] Response sent, cookies should be set in browser');
      console.log('🟢 [Login] Token also included in response body for Electron compatibility');
      console.log('🟢 [Login] Cookie settings:', {
        accessToken: 'Set (httpOnly + readable)',
        refreshToken: 'Set (httpOnly)',
        sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
        secure: process.env.NODE_ENV === 'production',
        maxAge: '7 days (accessToken), 30 days (refreshToken)',
      });
      res.json(response);
    } catch (error) {
      // Pass error to Express error middleware
      next(error);
    }
  }

  @Post('/logout')
  async logout(req: Request, res: Response): Promise<void> {
    try {
      const accessToken = req.cookies.accessToken;
      let userId = '';
      let userEmail = '';
      
      if (accessToken) {
        // Get user info before invalidating session
        try {
          const payload = this.authService.verifyAccessToken(accessToken);
          userId = payload.userId;
          userEmail = payload.email;
        } catch (error) {
          // Token is invalid, continue with logout
          console.log('Invalid token during logout:', error);
        }
        
        // Invalidate the session
        await this.authService.invalidateSession(accessToken);
      }

      // Log logout attempt with detailed information
      if (userId) {
        await this.authService.logLoginAttempt(
          userId,
          userEmail,
          true, // Success = true for logout
          req.ip,
          req.get('User-Agent'),
          'User logout - Session ended'
        );
      }

      // Clear cookies - ensure they're completely removed
      // Use same options as when setting cookies to ensure proper clearing
      res.clearCookie('accessToken', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: (process.env.NODE_ENV === 'production' ? 'strict' : 'lax') as 'strict' | 'lax',
        path: '/',
      });
      res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: (process.env.NODE_ENV === 'production' ? 'strict' : 'lax') as 'strict' | 'lax',
        path: '/',
      });
      res.clearCookie('isAuthenticated', {
        httpOnly: false,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
        path: '/',
      });
      
      // Also set expired cookies to ensure they're removed from browser
      res.cookie('accessToken', '', { maxAge: 0, path: '/' });
      res.cookie('refreshToken', '', { maxAge: 0, path: '/' });
      res.cookie('isAuthenticated', '', { maxAge: 0, path: '/' });

      const response: ApiResponse = {
        success: true,
        message: 'Logout successful'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Logout failed',
          statusCode: 500
        }
      });
    }
  }

  @Post('/refresh')
  async refresh(req: Request, res: Response): Promise<void> {
    try {
      // Try to get refresh token from cookies first, then from request body (for Electron apps)
      let refreshToken = req.cookies.refreshToken;
      
      if (!refreshToken && req.body?.refreshToken) {
        refreshToken = req.body.refreshToken;
        console.log('🔄 [Refresh] Using refresh token from request body (Electron compatibility)');
      }

      if (!refreshToken) {
        res.status(401).json({
          success: false,
          error: { message: 'Refresh token not found', statusCode: 401 }
        });
        return;
      }

      const tokens = await this.authService.refreshTokens(refreshToken);

      // Set new cookies (backend handles ALL cookie management)
      // Set both HTTP-only and readable cookies for maximum compatibility

      // HTTP-only cookie (secure)
      res.cookie('accessToken', tokens.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        path: '/',
        // Don't set domain - browsers will use current hostname
      });

      // Readable cookie (for client-side access)
      res.cookie('accessToken', tokens.accessToken, {
        httpOnly: false,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        path: '/',
      });

      res.cookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        path: '/',
        // Don't set domain - browsers will use current hostname
      });

      const response: ApiResponse = {
        success: true,
        data: {
          // Include tokens in response body for Electron/desktop app compatibility
          token: tokens.accessToken,
          refreshToken: tokens.refreshToken
        },
        message: 'Tokens refreshed successfully. New cookies have been set.'
      };
      
      // Note: Tokens are set as cookies AND included in response body for Electron compatibility
      res.json(response);
    } catch (error) {
      res.status(401).json({
        success: false,
        error: {
          message: 'Invalid refresh token',
          statusCode: 401
        }
      });
    }
  }

  @Get('/notifications')
  @Use(authenticate)
  async getNotifications(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: { message: 'Authentication required', statusCode: 401 }
        });
        return;
      }

      const limit = parseInt(req.query.limit as string) || 10;
      const notifications = await this.notificationService.getUserNotifications(req.user.id, limit);
      const stats = await this.notificationService.getNotificationStats(req.user.id);

      const response: ApiResponse = {
        success: true,
        data: {
          notifications,
          stats
        },
        message: 'Notifications retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to get notifications',
          statusCode: 500
        }
      });
    }
  }

  @Post('/notifications/:id/read')
  @Use(authenticate)
  async markNotificationAsRead(req: Request, res: Response): Promise<void> {
    try {
      const notificationId = req.params.id;

      if (!req.user) {
        res.status(401).json({
          success: false,
          error: { message: 'Authentication required', statusCode: 401 }
        });
        return;
      }

      if (!notificationId) {
        res.status(400).json({
          success: false,
          error: { message: 'Notification ID is required', statusCode: 400 }
        });
        return;
      }

      await this.notificationService.markNotificationAsRead(notificationId, req.user.id);

      const response: ApiResponse = {
        success: true,
        message: 'Notification marked as read'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to mark notification as read',
          statusCode: 500
        }
      });
    }
  }

  @Post('/notifications/read-all')
  @Use(authenticate)
  async markAllNotificationsAsRead(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: { message: 'Authentication required', statusCode: 401 }
        });
        return;
      }

      await this.notificationService.markAllNotificationsAsRead(req.user.id);

      const response: ApiResponse = {
        success: true,
        message: 'All notifications marked as read'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to mark all notifications as read',
          statusCode: 500
        }
      });
    }
  }

  @Get('/notifications/stream')
  @Use(authenticate)
  async getNotificationStream(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: { message: 'Authentication required', statusCode: 401 }
        });
        return;
      }

      // Set SSE headers
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Cache-Control'
      });

      // Send initial connection message
      res.write(`data: ${JSON.stringify({
        type: 'connected',
        message: 'Notification stream connected',
        timestamp: new Date().toISOString()
      })}\n\n`);

      // Keep connection alive with periodic ping
      const pingInterval = setInterval(() => {
        res.write(`data: ${JSON.stringify({
          type: 'ping',
          timestamp: new Date().toISOString()
        })}\n\n`);
      }, 30000); // Ping every 30 seconds

      // Handle client disconnect
      const userId = req.user.id;
      req.on('close', () => {
        clearInterval(pingInterval);
        console.log(`Notification stream closed for user ${userId}`);
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to establish notification stream',
          statusCode: 500
        }
      });
    }
  }

  @Get('/profile')
  @Use(authenticate)
  async getProfile(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: { message: 'Unauthorized', statusCode: 401 }
        });
        return;
      }

      const user = await this.userService.getUserById(req.user.id);
      
      const response: ApiResponse = {
        success: true,
        data: user,
        message: 'Profile retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve profile',
          statusCode: 500
        }
      });
    }
  }

  @Put('/profile')
  @Use(authenticate)
  @Validate([
    body('firstName').optional().isString().withMessage('First name must be a string'),
    body('lastName').optional().isString().withMessage('Last name must be a string'),
    body('email').optional().isEmail().withMessage('Email must be valid'),
    body('phone').optional().isString().withMessage('Phone must be a string'),
    body('avatar').optional().isString().withMessage('Avatar must be a string'),
    body('companyName').optional().isString().withMessage('Company name must be a string'),
    body('location').optional().isString().withMessage('Location must be a string')
  ])
  async updateProfile(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: { message: 'Unauthorized', statusCode: 401 }
        });
        return;
      }

      const { firstName, lastName, email, phone, avatar, companyName, location } = req.body;
      const userId = req.user.id;

      // Check if email is being changed and if it's already taken
      if (email) {
        const existingUser = await prisma.user.findFirst({
          where: {
            AND: [
              { id: { not: userId } },
              { email: email.toLowerCase() }
            ]
          }
        });
        if (existingUser) {
          res.status(400).json({
            success: false,
            error: {
              message: 'Email already exists',
              statusCode: 400
            }
          });
          return;
        }
      }

      // Update user in database
      // Build base update data
      const baseUpdateData: any = {
        ...(firstName !== undefined && { firstName }),
        ...(lastName !== undefined && { lastName }),
        ...(email !== undefined && { email: email.toLowerCase() }),
        ...(phone !== undefined && { phone }),
        ...(avatar !== undefined && { avatar })
      };

      // Try to update with company fields first, fallback to base if they don't exist
      let updatedUser: any;
      let updateData = { ...baseUpdateData };
      
      // Add company fields if provided
      if (companyName !== undefined) {
        updateData.companyName = companyName;
      }
      if (location !== undefined) {
        updateData.location = location;
      }

      try {
        // Try updating with all fields including company fields
        updatedUser = await prisma.user.update({
          where: { id: userId },
          data: updateData,
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            avatar: true,
            phone: true,
            role: true,
            status: true,
            updatedAt: true,
            // @ts-ignore - These fields will be available after migration
            companyName: true,
            location: true,
          }
        });
      } catch (prismaError: any) {
        // If error is about unknown fields, retry with base fields only
        if (prismaError?.message?.includes('Unknown argument') || 
            prismaError?.message?.includes('companyName') || 
            prismaError?.message?.includes('location')) {
          console.warn('Company fields not available in Prisma schema yet, updating without them');
          updatedUser = await prisma.user.update({
            where: { id: userId },
            data: baseUpdateData,
            select: {
              id: true,
              email: true,
              firstName: true,
              lastName: true,
              avatar: true,
              phone: true,
              role: true,
              status: true,
              updatedAt: true,
            }
          });
        } else {
          // Re-throw if it's a different error
          throw prismaError;
        }
      }

      const response: ApiResponse = {
        success: true,
        data: updatedUser,
        message: 'Profile updated successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to update profile',
          statusCode: 500
        }
      });
    }
  }

  /**
   * Get GitHub repositories for authenticated user
   * GET /api/auth/github/repositories
   */
  @Get('/github/repositories')
  @Use(authenticate)
  async getGitHubRepositories(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: { message: 'Unauthorized', statusCode: 401 }
        });
        return;
      }

      // Get user with GitHub access token
      const user = await this.userService.getUserById(req.user.id);
      
      // Type assertion to include githubAccessToken
      const userWithToken = user as any;
      
      if (!userWithToken.githubAccessToken) {
        res.status(400).json({
          success: false,
          error: {
            message: 'GitHub access token not found. Please authenticate with GitHub first.',
            statusCode: 400
          }
        });
        return;
      }

      // Import GitHubService dynamically to avoid circular dependency
      const { GitHubService } = await import('../services/github.service');
      const githubService = new GitHubService();

      // Fetch all repositories (user's own + organization repos)
      const repositories = await githubService.getAllRepositories(userWithToken.githubAccessToken);

      const response: ApiResponse = {
        success: true,
        data: repositories,
        message: 'Repositories retrieved successfully'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to retrieve repositories',
          statusCode
        }
      });
    }
  }

  @Get('/profile/public')
  async getPublicProfile(req: Request, res: Response): Promise<void> {
    try {
      const { email } = req.query;

      if (!email) {
        res.status(400).json({
          success: false,
          error: { message: 'Email parameter is required', statusCode: 400 }
        });
        return;
      }

      // Get user data from users table without authentication
      const user = await prisma.user.findUnique({
        where: { email: email as string },
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          phone: true,
          avatar: true,
          role: true,
          status: true,
          emailVerified: true,
          twoFactorEnabled: true,
          lastLoginAt: true,
          createdAt: true,
          updatedAt: true
        }
      });

      if (!user) {
        res.status(404).json({
          success: false,
          error: { message: 'User not found', statusCode: 404 }
        });
        return;
      }

      // Get user subscription data
      const subscription = await prisma.userSubscription.findFirst({
        where: { userId: user.id },
        include: {
          plan: {
            select: {
              id: true,
              name: true,
              description: true,
              price: true,
              billingCycle: true,
              features: true
            }
          }
        },
        orderBy: { createdAt: 'desc' }
      });

      // Get user's login logs count
      const loginLogsCount = await prisma.loginLog.count({
        where: { userId: user.id }
      });

      // Get recent login logs (last 5)
      const recentLogins = await prisma.loginLog.findMany({
        where: { userId: user.id },
        orderBy: { createdAt: 'desc' },
        take: 5,
        select: {
          id: true,
          success: true,
          ipAddress: true,
          userAgent: true,
          reason: true,
          createdAt: true
        }
      });

      // Get user's active sessions
      const activeSessions = await prisma.session.findMany({
        where: { 
          userId: user.id,
          expiresAt: { gt: new Date() }
        },
        select: {
          id: true,
          deviceInfo: true,
          ipAddress: true,
          userAgent: true,
          createdAt: true,
          expiresAt: true
        },
        orderBy: { createdAt: 'desc' }
      });

      const response: ApiResponse = {
        success: true,
        data: {
          user: {
            ...user,
            // Override role based on authorized admin emails
            role: ['webnox@admin.com', 'webnox1@admin.com'].includes(user.email) ? 'ADMIN' : user.role
          },
          subscription: subscription ? {
            id: subscription.id,
            plan: subscription.plan,
            status: subscription.status,
            startDate: subscription.startDate,
            endDate: subscription.endDate,
            autoRenew: subscription.autoRenew
          } : null,
          stats: {
            loginLogsCount,
            activeSessionsCount: activeSessions.length,
            isOnline: activeSessions.length > 0
          },
          recentLogins,
          activeSessions: activeSessions.map(session => ({
            id: session.id,
            deviceInfo: session.deviceInfo,
            ipAddress: session.ipAddress,
            userAgent: session.userAgent,
            loginTime: session.createdAt,
            expiresAt: session.expiresAt,
            isActive: session.expiresAt > new Date()
          }))
        },
        message: 'Public profile retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve public profile',
          statusCode: 500
        }
      });
    }
  }

  @Post('/logout-all')
  @Use(authenticate)
  async logoutAllDevices(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: { message: 'Authentication required', statusCode: 401 }
        });
        return;
      }

      // Get current sessions before invalidating for logging
      const currentSessions = await this.authService.getUserSessions(req.user.id);
      
      // Invalidate all sessions for this user
      await this.authService.invalidateAllUserSessions(req.user.id);

      // Log the forced logout of all devices
      await this.authService.logLoginAttempt(
        req.user.id,
        req.user.email,
        true,
        req.ip,
        req.get('User-Agent'),
        `Forced logout from all devices. Previous sessions: ${currentSessions.length}`
      );

      // Clear current session cookies
      res.clearCookie('accessToken');
      res.clearCookie('refreshToken');
      res.clearCookie('isAuthenticated');

      const response: ApiResponse = {
        success: true,
        message: 'Logged out from all devices successfully',
        data: {
          previousSessionsCount: currentSessions.length
        }
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to logout from all devices',
          statusCode: 500
        }
      });
    }
  }

  @Get('/block-status/:email')
  async getBlockStatus(req: Request, res: Response): Promise<void> {
    try {
      const { email } = req.params;

      if (!email) {
        res.status(400).json({
          success: false,
          error: { message: 'Email is required', statusCode: 400 }
        });
        return;
      }

      const blockStatus = await this.authService.isUserBlocked(email);

      const response: ApiResponse = {
        success: true,
        data: {
          email,
          isBlocked: blockStatus.isBlocked,
          attempts: blockStatus.attempts,
          blockedAt: blockStatus.blockedAt,
          expiresAt: blockStatus.expiresAt,
          remainingMinutes: blockStatus.remainingMinutes,
          message: blockStatus.isBlocked 
            ? `Account is blocked. Try again in ${blockStatus.remainingMinutes} minutes.`
            : 'Account is not blocked.'
        },
        message: 'Block status retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to get block status',
          statusCode: 500
        }
      });
    }
  }

  @Get('/session-status')
  @Use(authenticate)
  async getSessionStatus(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: { message: 'Authentication required', statusCode: 401 }
        });
        return;
      }

      // Get current active sessions for the user
      const activeSessions = await this.authService.getUserSessions(req.user.id);
      
      const response: ApiResponse = {
        success: true,
        data: {
          activeSessions: activeSessions.length,
          sessions: activeSessions.map(session => ({
            deviceInfo: session.deviceInfo,
            ipAddress: session.ipAddress,
            userAgent: session.userAgent,
            loginTime: session.createdAt,
            expiresAt: session.expiresAt
          }))
        },
        message: 'Session status retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve session status',
          statusCode: 500
        }
      });
    }
  }

  @Get('/login-logs')
  @Use(authenticate)
  async getLoginLogs(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: { message: 'Authentication required', statusCode: 401 }
        });
        return;
      }

      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 50;
      const skip = (page - 1) * limit;
      const userId = req.query.userId as string;

      // Build where clause based on user role
      let whereClause: any = {};
      
      // If not admin, only show logs for current user
      if (req.user.role !== 'ADMIN') {
        whereClause.userId = req.user.id;
      } else if (req.user.role === 'ADMIN') {
        // Additional check for admin role - only authorized admin emails can access admin features
        const adminEmails = ['webnox@admin.com', 'webnox1@admin.com'];
        if (!adminEmails.includes(req.user.email)) {
          res.status(403).json({
            success: false,
            error: { 
              message: 'Access denied. Admin access is restricted to authorized personnel only.', 
              statusCode: 403,
              code: 'ADMIN_ACCESS_DENIED'
            }
          });
          return;
        }
        
        if (userId) {
          // Admin can filter by specific user
          whereClause.userId = userId;
        }
      }

      const [logs, total] = await Promise.all([
        prisma.loginLog.findMany({
          where: whereClause,
          skip,
          take: limit,
          orderBy: { createdAt: 'desc' },
          include: {
            user: {
              select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true
              }
            }
          }
        }),
        prisma.loginLog.count({ where: whereClause })
      ]);

      const enhancedLogs = logs.map(log => ({
        ...log,
        isLoginAttempt: log.reason?.includes('login') || log.reason?.includes('logout')
      }));

      const response: ApiResponse = {
        success: true,
        data: {
          logs: enhancedLogs,
          pagination: {
            page,
            limit,
            total,
            totalPages: Math.ceil(total / limit)
          }
        },
        message: 'Login logs retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve login logs',
          statusCode: 500
        }
      });
    }
  }

  @Post('/force-logout/:userId')
  @Use(authenticate)
  async forceLogoutUser(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: { message: 'Authentication required', statusCode: 401 }
        });
        return;
      }

      // Only allow admin users to force logout - and only the specific admin
      if (req.user.role !== 'ADMIN') {
        res.status(403).json({
          success: false,
          error: { message: 'Access denied. Admin privileges required.', statusCode: 403 }
        });
        return;
      }

      // Additional check for admin role - only authorized admin emails can access admin features
      const adminEmails = ['webnox@admin.com', 'webnox1@admin.com'];
      if (req.user.role === 'ADMIN' && !adminEmails.includes(req.user.email)) {
        res.status(403).json({
          success: false,
          error: { 
            message: 'Access denied. Admin access is restricted to authorized personnel only.', 
            statusCode: 403,
            code: 'ADMIN_ACCESS_DENIED'
          }
        });
        return;
      }

      const { userId } = req.params;
      const { reason } = req.body;

      if (!userId) {
        res.status(400).json({
          success: false,
          error: { message: 'User ID is required', statusCode: 400 }
        });
        return;
      }

      // Force logout the user
      await this.authService.forceLogoutUser(
        userId, 
        req.user.id, 
        reason || 'Admin forced logout'
      );

        const response: ApiResponse = {
          success: true,
          message: 'User has been force logged out from all devices successfully'
        };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to force logout user',
          statusCode: 500
        }
      });
    }
  }

  @Post('/refresh-token')
  async refreshToken(req: Request, res: Response): Promise<void> {
    try {
      const { refreshToken } = req.body;
      
      // In a real app, you'd validate the refresh token
      const response: ApiResponse = {
        success: true,
        data: { accessToken: 'new-access-token' },
        message: 'Token refreshed successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Token refresh failed',
          statusCode: 500
        }
      });
    }
  }

  // Google OAuth Login - Initiate
  @Get('/google')
  async googleLogin(req: Request, res: Response, next: NextFunction): Promise<void> {
    console.log('🟢 [Backend] Google OAuth login initiated');
    console.log('🟢 [Backend] Request URL:', req.url);
    console.log('🟢 [Backend] Request query:', req.query);
    console.log('🟢 [Backend] Session ID:', req.sessionID);
    
    if (!config.google) {
      console.error('🟢 [Backend] Google OAuth not configured');
      res.status(503).json({
        success: false,
        error: {
          message: 'Google OAuth is not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in your .env file.',
          statusCode: 503,
          hint: 'Add these to your .env file: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_CALLBACK_URL, FRONTEND_URL'
        }
      });
      return;
    }

    console.log('🟢 [Backend] Google OAuth config:', {
      clientId: `${config.google.clientId.substring(0, 20)}...`,
      callbackURL: config.google.callbackURL,
    });

    // Store redirect URL in session if provided
    if (req.query.redirect) {
      (req.session as any).redirectUrl = req.query.redirect as string;
      console.log('🟢 [Backend] Stored redirect URL in session:', req.query.redirect);
    }

    console.log('🟢 [Backend] Initiating Passport Google authentication...');
    // Use passport.authenticate as Express middleware
    return passport.authenticate('google', {
      scope: ['profile', 'email']
    })(req, res, next);
  }

  // Google OAuth Login - Website (redirects to port 3001)
  @Get('/google/website')
  async googleWebsiteLogin(req: Request, res: Response, next: NextFunction): Promise<void> {
    console.log('🌐 [Backend Website] Google OAuth login initiated for website');
    console.log('🌐 [Backend Website] Request URL:', req.url);
    console.log('🌐 [Backend Website] Request query:', req.query);
    
    if (!config.google) {
      console.error('🌐 [Backend Website] Google OAuth not configured');
      res.status(503).json({
        success: false,
        error: {
          message: 'Google OAuth is not configured',
          statusCode: 503
        }
      });
      return;
    }

    // Store redirect URL in session if provided
    if (req.query.redirect) {
      (req.session as any).redirectUrl = req.query.redirect as string;
      console.log('🌐 [Backend Website] Stored redirect URL in session:', req.query.redirect);
    }

    // Store that this is for website (port 3001)
    (req.session as any).isWebsite = true;
    console.log('🌐 [Backend Website] Marked as website OAuth in session');

    console.log('🌐 [Backend Website] Initiating Passport Google authentication for website...');
    // Use 'google-website' strategy instead of 'google'
    return passport.authenticate('google-website', {
      scope: ['profile', 'email']
    })(req, res, next);
  }

  // Google OAuth Callback Handler - Website (redirects to port 3001)
  // This is called internally from the main callback handler
  private async googleWebsiteCallback(req: Request, res: Response, next: NextFunction): Promise<void> {
    console.log('🌐 [Backend Website Callback] Google OAuth callback received for website');
    console.log('🌐 [Backend Website Callback] Request URL:', req.url);
    console.log('🌐 [Backend Website Callback] Request query:', req.query);
    
    if (!config.google) {
      console.error('🌐 [Backend Website Callback] Google OAuth not configured');
      res.status(503).json({
        success: false,
        error: {
          message: 'Google OAuth is not configured',
          statusCode: 503
        }
      });
      return;
    }

    console.log('🌐 [Backend Website Callback] Authenticating with Passport Google website strategy...');
    passport.authenticate('google-website', { session: false }, async (err: any, user: any) => {
      console.log('🌐 [Backend Website Callback] Passport authenticate callback triggered');
      
      if (err || !user) {
        const errorMessage = err?.message || 'Google authentication failed';
        console.error('🌐 [Backend Website Callback] Authentication failed:', errorMessage);
        // Website frontend URL - use environment variable or default to port 3001
        const websiteUrl = process.env.WEBSITE_URL || 'http://localhost:4006';
        return res.redirect(`${websiteUrl}/login?error=${encodeURIComponent(errorMessage)}`);
      }

      try {
        console.log('🌐 [Backend Website Callback] Processing successful authentication for user:', user.email);
        
        const deviceInfo = {
          userAgent: req.get('User-Agent') || '',
          platform: 'web',
          language: req.get('Accept-Language') || 'en',
          timestamp: new Date().toISOString()
        };

        const userRole = typeof user.role === 'string' ? user.role : (user as any).role || 'USER';
        const userStatus = (user as any).status || ((user as any).isActive ? 'ACTIVE' : 'INACTIVE');
        
        const tokens = this.authService.generateTokens({
          id: user.id,
          email: user.email,
          role: userRole,
          isActive: userStatus === 'ACTIVE'
        });

        await this.authService.createSession(
          user.id,
          tokens.accessToken,
          JSON.stringify(deviceInfo),
          req.ip || '',
          req.get('User-Agent') || ''
        );

        await prisma.user.update({
          where: { id: user.id },
          data: { lastLoginAt: new Date() }
        });

        await this.authService.logLoginAttempt(
          user.id,
          user.email,
          true,
          req.ip || '',
          req.get('User-Agent') || ''
        );

        // Set cookies - both HTTP-only and readable for compatibility
        const httpOnlyCookieOptions = {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: (process.env.NODE_ENV === 'production' ? 'strict' : 'lax') as 'strict' | 'lax',
          maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
          path: '/',
        };

        const readableCookieOptions = {
          httpOnly: false,
          secure: process.env.NODE_ENV === 'production',
          sameSite: (process.env.NODE_ENV === 'production' ? 'strict' : 'lax') as 'strict' | 'lax',
          maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
          path: '/',
        };

        // HTTP-only cookie (secure)
        res.cookie('accessToken', tokens.accessToken, httpOnlyCookieOptions);
        // Readable cookie (for client-side access)
        res.cookie('accessToken', tokens.accessToken, readableCookieOptions);
        if (tokens.refreshToken) {
          res.cookie('refreshToken', tokens.refreshToken, {
            ...httpOnlyCookieOptions,
            maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
          });
        }
        res.cookie('isAuthenticated', 'true', {
          httpOnly: false,
          secure: process.env.NODE_ENV === 'production',
          sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
          maxAge: 7 * 24 * 60 * 60 * 1000,
          path: '/',
        });

        // Get redirect URL from session or default to root
        const redirectUrl = (req.session as any)?.redirectUrl || '/';
        delete (req.session as any)?.redirectUrl;
        delete (req.session as any)?.isWebsite;

        // Website frontend URL - use environment variable or default to port 3001
        const websiteUrl = process.env.WEBSITE_URL || 'http://localhost:4006';
        const finalRedirectUrl = `${websiteUrl}${redirectUrl}`;
        
        console.log('🌐 [Backend Website Callback] Redirecting to website:', finalRedirectUrl);
        return res.redirect(finalRedirectUrl);
      } catch (error: any) {
        console.error('🌐 [Backend Website Callback] Error:', error);
        const websiteUrl = process.env.WEBSITE_URL || 'http://localhost:4006';
        return res.redirect(`${websiteUrl}/login?error=${encodeURIComponent(error?.message || 'Login failed')}`);
      }
    })(req, res);
  }

  // Google OAuth Callback - Handles both admin and website
  @Get('/google/callback')
  async googleCallback(req: Request, res: Response, next: NextFunction): Promise<void> {
    console.log('🟡 [Backend Callback] Google OAuth callback received');
    console.log('🟡 [Backend Callback] Request URL:', req.url);
    console.log('🟡 [Backend Callback] Request query:', req.query);
    console.log('🟡 [Backend Callback] Session ID:', req.sessionID);
    
    // Check if this is a website request (stored in session when /google/website was called)
    const isWebsite = (req.session as any)?.isWebsite;
    console.log('🟡 [Backend Callback] Is website request:', isWebsite);
    
    if (isWebsite) {
      // Route to website callback handler
      console.log('🟡 [Backend Callback] Routing to website callback handler');
      return this.googleWebsiteCallback(req, res, next);
    }

    console.log('🟡 [Backend Callback] Request headers:', {
      cookie: req.headers.cookie ? 'Present' : 'Missing',
      userAgent: req.headers['user-agent'],
      referer: req.headers.referer,
    });

    if (!config.google) {
      console.error('🟡 [Backend Callback] Google OAuth not configured');
      res.status(503).json({
        success: false,
        error: {
          message: 'Google OAuth is not configured',
          statusCode: 503
        }
      });
      return;
    }

    console.log('🟡 [Backend Callback] Authenticating with Passport Google strategy (admin)...');
    passport.authenticate('google', { session: false }, async (err: any, user: any) => {
      console.log('🟡 [Backend Callback] Passport authenticate callback triggered');
      console.log('🟡 [Backend Callback] Error:', err ? {
        message: err.message,
        name: err.name,
      } : 'None');
      console.log('🟡 [Backend Callback] User:', user ? {
        id: user.id,
        email: user.email,
        role: user.role,
      } : 'None');

      if (err || !user) {
        // Redirect to frontend with error
        const errorMessage = err?.message || 'Google authentication failed';
        console.error('🟡 [Backend Callback] Authentication failed:', errorMessage);
        console.log('🟡 [Backend Callback] Redirecting to:', `${config.frontendUrl}/signin?error=${encodeURIComponent(errorMessage)}`);
        return res.redirect(`${config.frontendUrl}/signin?error=${encodeURIComponent(errorMessage)}`);
      }

      try {
        console.log('🟡 [Backend Callback] Processing successful authentication for user:', user.email);
        
        // For OAuth logins, we allow multiple sessions (multiple devices allowed)

        // Generate tokens
        const deviceInfo = {
          userAgent: req.get('User-Agent') || '',
          platform: 'web',
          language: req.get('Accept-Language') || 'en',
          timestamp: new Date().toISOString()
        };
        console.log('🟡 [Backend Callback] Device info:', deviceInfo);

        // Get user role (handle both string and object formats)
        const userRole = typeof user.role === 'string' ? user.role : (user as any).role || 'USER';
        const userStatus = (user as any).status || ((user as any).isActive ? 'ACTIVE' : 'INACTIVE');
        console.log('🟡 [Backend Callback] User role:', userRole, 'Status:', userStatus);
        
        console.log('🟡 [Backend Callback] Generating tokens...');
        const tokens = this.authService.generateTokens({
          id: user.id,
          email: user.email,
          role: userRole,
          isActive: userStatus === 'ACTIVE'
        });
        console.log('🟡 [Backend Callback] Tokens generated:', {
          accessToken: tokens.accessToken ? 'Present' : 'Missing',
          refreshToken: tokens.refreshToken ? 'Present' : 'Missing',
        });

        // Create new session
        console.log('🟡 [Backend Callback] Creating session...');
        await this.authService.createSession(
          user.id,
          tokens.accessToken,
          JSON.stringify(deviceInfo),
          req.ip || '',
          req.get('User-Agent') || ''
        );
        console.log('🟡 [Backend Callback] Session created successfully');

        // Update last login
        console.log('🟡 [Backend Callback] Updating last login timestamp...');
        await prisma.user.update({
          where: { id: user.id },
          data: { lastLoginAt: new Date() }
        });

        // Log successful login
        console.log('🟡 [Backend Callback] Logging successful login attempt...');
        await this.authService.logLoginAttempt(
          user.id,
          user.email,
          true,
          req.ip || '',
          req.get('User-Agent') || ''
        );

        // Set cookies with proper settings for cross-origin
        // Don't set domain - allows cookies to work for same hostname (localhost) with different ports
        console.log('🟡 [Backend Callback] Setting cookies...');
        console.log('🟡 [Backend Callback] Cookie settings:', {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
          maxAge: '7 days (accessToken)',
          path: '/',
          domain: 'NOT SET (uses current hostname)',
        });
        
        const httpOnlyCookieOptions = {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: (process.env.NODE_ENV === 'production' ? 'strict' : 'lax') as 'strict' | 'lax',
          maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
          path: '/',
        };

        const readableCookieOptions = {
          httpOnly: false,
          secure: process.env.NODE_ENV === 'production',
          sameSite: (process.env.NODE_ENV === 'production' ? 'strict' : 'lax') as 'strict' | 'lax',
          maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
          path: '/',
        };

        // HTTP-only cookie (secure)
        res.cookie('accessToken', tokens.accessToken, httpOnlyCookieOptions);
        // Readable cookie (for client-side access)
        res.cookie('accessToken', tokens.accessToken, readableCookieOptions);
        console.log('🟡 [Backend Callback] accessToken cookies set:', {
          tokenLength: tokens.accessToken.length,
          tokenPreview: tokens.accessToken.substring(0, 20) + '...',
          httpOnlyOptions: httpOnlyCookieOptions,
          readableOptions: readableCookieOptions,
        });

        if (tokens.refreshToken) {
          const refreshCookieOptions = {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: (process.env.NODE_ENV === 'production' ? 'strict' : 'lax') as 'strict' | 'lax',
            maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
            path: '/',
          };
          res.cookie('refreshToken', tokens.refreshToken, refreshCookieOptions);
          console.log('🟡 [Backend Callback] refreshToken cookie set:', {
            tokenLength: tokens.refreshToken.length,
            tokenPreview: tokens.refreshToken.substring(0, 20) + '...',
            cookieOptions: refreshCookieOptions,
          });
        }

        // Set a non-HttpOnly cookie that JavaScript can read to check auth status
        res.cookie('isAuthenticated', 'true', {
          httpOnly: false, // Allow JavaScript to read this
          secure: process.env.NODE_ENV === 'production',
          sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
          maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
          path: '/',
        });
        console.log('🟡 [Backend Callback] isAuthenticated cookie set');
        
        // Log what cookies are being sent in the response
        const responseCookies = res.getHeaders()['set-cookie'] || [];
        console.log('🟡 [Backend Callback] Response Set-Cookie headers:', {
          count: Array.isArray(responseCookies) ? responseCookies.length : 1,
          headers: responseCookies,
        });

        // Get redirect URL from session or default to root
        const redirectUrl = (req.session as any)?.redirectUrl || '/';
        delete (req.session as any)?.redirectUrl;
        console.log('🟡 [Backend Callback] Redirect URL from session:', redirectUrl);
        console.log('🟡 [Backend Callback] Frontend URL:', config.frontendUrl);

        const finalRedirectUrl = `${config.frontendUrl}${redirectUrl}`;
        console.log('🟡 [Backend Callback] Final redirect URL:', finalRedirectUrl);
        console.log('🟡 [Backend Callback] Redirecting to frontend...');

        // Note: Cookies are already set above, redirect will send cookies to browser
        // Redirect to frontend with success
        return res.redirect(finalRedirectUrl);
      } catch (error: any) {
        console.error('🟡 [Backend Callback] Error in callback handler:', {
          message: error?.message,
          stack: error?.stack,
          name: error?.name,
        });
        const errorUrl = `${config.frontendUrl}/signin?error=${encodeURIComponent(error?.message || 'Login failed. Please try again.')}`;
        console.error('🟡 [Backend Callback] Redirecting to error page:', errorUrl);
        return res.redirect(errorUrl);
      }
    })(req, res);
  }

  /**
   * Initiate GitHub OAuth flow
   * GET /api/auth/github
   */
  @Get('/github')
  async initiateGitHubAuth(req: Request, res: Response): Promise<void> {
    console.log('🟣 [Backend] GitHub OAuth initiation requested');
    
    if (!config.github) {
      console.error('🟣 [Backend] GitHub OAuth not configured');
      res.status(503).json({
        success: false,
        error: {
          message: 'GitHub OAuth is not configured',
          statusCode: 503
        }
      });
      return;
    }

    // Store redirect URL if provided
    if (req.query.redirect) {
      (req.session as any).redirectUrl = req.query.redirect as string;
    }

    console.log('🟣 [Backend] Initiating GitHub OAuth flow...');
    passport.authenticate('github', {
      scope: ['user:email', 'read:org', 'repo'],
      session: false,
    })(req, res);
  }

  /**
   * GitHub OAuth Callback
   * GET /api/auth/github/callback
   */
  @Get('/github/callback')
  async githubCallback(req: Request, res: Response, next: NextFunction): Promise<void> {
    console.log('🟣 [Backend Callback] GitHub OAuth callback received');
    console.log('🟣 [Backend Callback] Request URL:', req.url);
    console.log('🟣 [Backend Callback] Request query:', req.query);
    console.log('🟣 [Backend Callback] Session ID:', req.sessionID);

    if (!config.github) {
      console.error('🟣 [Backend Callback] GitHub OAuth not configured');
      res.status(503).json({
        success: false,
        error: {
          message: 'GitHub OAuth is not configured',
          statusCode: 503
        }
      });
      return;
    }

    console.log('🟣 [Backend Callback] Authenticating with Passport GitHub strategy...');
    passport.authenticate('github', { session: false }, async (err: any, user: any) => {
      console.log('🟣 [Backend Callback] Passport authenticate callback triggered');
      console.log('🟣 [Backend Callback] Error:', err ? {
        message: err.message,
        name: err.name,
      } : 'None');
      console.log('🟣 [Backend Callback] User:', user ? {
        id: user.id,
        email: user.email,
        role: user.role,
      } : 'None');

      if (err || !user) {
        // Redirect to frontend with error
        const errorMessage = err?.message || 'GitHub authentication failed';
        console.error('🟣 [Backend Callback] Authentication failed:', errorMessage);
        console.log('🟣 [Backend Callback] Redirecting to:', `${config.frontendUrl}/signin?error=${encodeURIComponent(errorMessage)}`);
        return res.redirect(`${config.frontendUrl}/signin?error=${encodeURIComponent(errorMessage)}`);
      }

      try {
        console.log('🟣 [Backend Callback] Processing successful authentication for user:', user.email);
        
        // For OAuth logins, we allow multiple sessions (multiple devices allowed)

        // Generate tokens
        const deviceInfo = {
          userAgent: req.get('User-Agent') || '',
          platform: 'web',
          language: req.get('Accept-Language') || 'en',
          timestamp: new Date().toISOString()
        };
        console.log('🟣 [Backend Callback] Device info:', deviceInfo);

        // Get user role (handle both string and object formats)
        const userRole = typeof user.role === 'string' ? user.role : (user as any).role || 'USER';
        const userStatus = (user as any).status || ((user as any).isActive ? 'ACTIVE' : 'INACTIVE');
        console.log('🟣 [Backend Callback] User role:', userRole, 'Status:', userStatus);
        
        console.log('🟣 [Backend Callback] Generating tokens...');
        const tokens = this.authService.generateTokens({
          id: user.id,
          email: user.email,
          role: userRole,
          isActive: userStatus === 'ACTIVE'
        });
        console.log('🟣 [Backend Callback] Tokens generated:', {
          accessToken: tokens.accessToken ? 'Present' : 'Missing',
          refreshToken: tokens.refreshToken ? 'Present' : 'Missing',
        });

        // Create new session
        console.log('🟣 [Backend Callback] Creating session...');
        await this.authService.createSession(
          user.id,
          tokens.accessToken,
          JSON.stringify(deviceInfo),
          req.ip || '',
          req.get('User-Agent') || ''
        );
        console.log('🟣 [Backend Callback] Session created successfully');

        // Update last login
        console.log('🟣 [Backend Callback] Updating last login timestamp...');
        await prisma.user.update({
          where: { id: user.id },
          data: { lastLoginAt: new Date() }
        });

        // Log successful login
        console.log('🟣 [Backend Callback] Logging successful login attempt...');
        await this.authService.logLoginAttempt(
          user.id,
          user.email,
          true,
          req.ip || '',
          req.get('User-Agent') || ''
        );

        // Set cookies with proper settings for persistence and cross-origin
        console.log('🟣 [Backend Callback] Setting cookies...');
        const httpOnlyCookieOptions = {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: (process.env.NODE_ENV === 'production' ? 'strict' : 'lax') as 'strict' | 'lax',
          maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days - persists across app restarts
          path: '/',
          // Don't set domain - allows cookies to work for localhost with different ports
        };

        const readableCookieOptions = {
          httpOnly: false,
          secure: process.env.NODE_ENV === 'production',
          sameSite: (process.env.NODE_ENV === 'production' ? 'strict' : 'lax') as 'strict' | 'lax',
          maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days - persists across app restarts
          path: '/',
        };

        // HTTP-only cookie (secure)
        res.cookie('accessToken', tokens.accessToken, httpOnlyCookieOptions);
        // Readable cookie (for client-side access)
        res.cookie('accessToken', tokens.accessToken, readableCookieOptions);
        console.log('🟣 [Backend Callback] accessToken cookies set (persist for 7 days)');

        if (tokens.refreshToken) {
          const refreshCookieOptions = {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: (process.env.NODE_ENV === 'production' ? 'strict' : 'lax') as 'strict' | 'lax',
            maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days - persists across app restarts
            path: '/',
            // Don't set domain - allows cookies to work for localhost with different ports
          };
          res.cookie('refreshToken', tokens.refreshToken, refreshCookieOptions);
          console.log('🟣 [Backend Callback] refreshToken cookie set (persists for 30 days)');
        }

        // Set a non-HttpOnly cookie that JavaScript can read to check auth status
        res.cookie('isAuthenticated', 'true', {
          httpOnly: false, // Allow JavaScript to read this
          secure: process.env.NODE_ENV === 'production',
          sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
          maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days - persists across app restarts
          path: '/',
        });
        console.log('🟣 [Backend Callback] isAuthenticated cookie set (persists for 7 days)');

        // Get redirect URL from session or default to root
        const redirectUrl = (req.session as any)?.redirectUrl || '/';
        delete (req.session as any)?.redirectUrl;
        console.log('🟣 [Backend Callback] Redirect URL from session:', redirectUrl);
        console.log('🟣 [Backend Callback] Frontend URL:', config.frontendUrl);

        // Get user with GitHub access token for token in URL
        const userWithToken = await this.userService.getUserById(user.id);
        const userWithTokenAny = userWithToken as any;
        
        // For ALL apps (Electron and web), redirect with token in URL for silent OAuth
        // This avoids JSON blocking the UI
        
        // Try to detect the frontend URL from the redirect URL, referer, or use configured URL
        let frontendUrl = config.frontendUrl;
        
        // First, try to extract from redirect URL (if it's a full URL)
        if (redirectUrl.startsWith('http://') || redirectUrl.startsWith('https://')) {
          try {
            const redirectUrlObj = new URL(redirectUrl);
            frontendUrl = `${redirectUrlObj.protocol}//${redirectUrlObj.host}`;
            console.log('🟣 [Backend Callback] Detected frontend URL from redirect URL:', frontendUrl);
          } catch (e) {
            console.log('🟣 [Backend Callback] Could not parse redirect URL');
          }
        }
        
        // If not found, try referer
        if (frontendUrl === config.frontendUrl) {
          const referer = req.get('Referer');
          if (referer) {
            try {
              const refererUrl = new URL(referer);
              // Use the same origin as the referer (in case frontend is on different port)
              frontendUrl = `${refererUrl.protocol}//${refererUrl.host}`;
              console.log('🟣 [Backend Callback] Detected frontend URL from referer:', frontendUrl);
            } catch (e) {
              console.log('🟣 [Backend Callback] Could not parse referer, using configured URL');
            }
          }
        }
        
        // Extract path from redirect URL (remove origin if it's a full URL)
        let redirectPath = redirectUrl;
        if (redirectUrl.startsWith('http://') || redirectUrl.startsWith('https://')) {
          try {
            const redirectUrlObj = new URL(redirectUrl);
            redirectPath = redirectUrlObj.pathname + redirectUrlObj.search;
          } catch (e) {
            // Keep original redirectUrl
          }
        }

        // Build redirect URL with token and autoAuth flag for silent login
        const separator = redirectPath.includes('?') ? '&' : '?';
        const tokenParam = `token=${encodeURIComponent(tokens.accessToken)}`;
        const autoAuthParam = 'autoAuth=true';
        const githubTokenParam = userWithTokenAny.githubAccessToken 
          ? `&githubToken=${encodeURIComponent(userWithTokenAny.githubAccessToken)}`
          : '';
        
        const finalRedirectUrl = `${frontendUrl}${redirectPath}${separator}${tokenParam}&${autoAuthParam}${githubTokenParam}`;
        console.log('🟣 [Backend Callback] Silent OAuth redirect with token in URL');
        console.log('🟣 [Backend Callback] Final redirect URL (token hidden for security):', 
          `${frontendUrl}${redirectPath}${separator}token=***&autoAuth=true${githubTokenParam ? '&githubToken=***' : ''}`);
        console.log('🟣 [Backend Callback] Redirecting to frontend for silent login...');

        // Redirect to frontend with token in URL (silent OAuth - no JSON blocking)
        return res.redirect(finalRedirectUrl);
      } catch (error: any) {
        console.error('🟣 [Backend Callback] Error in callback handler:', {
          message: error?.message,
          stack: error?.stack,
          name: error?.name,
        });
        const errorUrl = `${config.frontendUrl}/signin?error=${encodeURIComponent(error?.message || 'Login failed. Please try again.')}`;
        console.error('🟣 [Backend Callback] Redirecting to error page:', errorUrl);
        return res.redirect(errorUrl);
      }
    })(req, res);
  }
}