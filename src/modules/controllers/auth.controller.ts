import { Request, Response, NextFunction } from 'express';
import { Controller, Post, Get, Delete } from '../../decorators/controller.decorator';
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
  async login(req: Request, res: Response): Promise<void> {
    try {
      const { email, password, deviceInfo } = req.body;

      console.log('req.body', req.body);
      
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
      
      const user = await this.userService.validateCredentials({ email, password });
      if (!user) {
        // Record failed login attempt and check for blocking (only in production mode)
        if (config.security.loginBlocking) {
          const blockResult = await this.authService.recordFailedLoginAttempt(
            email,
            req.ip,
            req.get('User-Agent'),
            'Invalid credentials'
          );

          // Log failed login attempt
          await this.authService.logLoginAttempt(
            '', // No userId for failed attempts
            email,
            false,
            req.ip,
            req.get('User-Agent'),
            `Invalid credentials. Attempt ${blockResult.attempts}/3`
          );
          
          if (blockResult.isBlocked) {
            res.status(423).json({
              success: false,
              error: { 
                message: `Account blocked after 3 failed attempts. Please try again in ${blockResult.remainingMinutes} minutes.`, 
                statusCode: 423,
                code: 'ACCOUNT_BLOCKED',
                details: {
                  attempts: blockResult.attempts,
                  remainingMinutes: blockResult.remainingMinutes
                }
              }
            });
          } else {
            res.status(401).json({
              success: false,
              error: { 
                message: `Invalid credentials. ${3 - blockResult.attempts} attempts remaining.`, 
                statusCode: 401,
                code: 'INVALID_CREDENTIALS',
                details: {
                  attempts: blockResult.attempts,
                  remainingAttempts: 3 - blockResult.attempts
                }
              }
            });
          }
        } else {
          // Simple error response
          res.status(401).json({
            success: false,
            error: { 
              message: 'Invalid credentials', 
              statusCode: 401,
              code: 'INVALID_CREDENTIALS'
            }
          });
        }
        return;
      }

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
        
        res.status(403).json({
          success: false,
          error: { 
            message: 'Access denied. Admin login is restricted to authorized personnel only.', 
            statusCode: 403,
            code: 'ADMIN_ACCESS_DENIED'
          }
        });
        return;
      }

      // Check if user already has an active session (Single Device Login Enforcement)
      // Only enforce in production mode or when explicitly enabled
      if (config.security.singleDeviceLogin) {
        const existingSessions = await this.authService.getUserSessions(user.id);
        if (existingSessions.length > 0) {
          // Get details of the existing session for better logging
          const existingSession = existingSessions[0];
          
          // Log failed login attempt due to existing session with detailed info
          await this.authService.logLoginAttempt(
            user.id,
            email,
            false,
            req.ip,
            req.get('User-Agent'),
            `User already logged in on another device. Existing session: ${existingSession.deviceInfo || 'Unknown Device'} (IP: ${existingSession.ipAddress || 'Unknown'})`
          );
          
          res.status(409).json({
            success: false,
            error: { 
              message: 'This account is already logged in on another device. Only one device can be logged in at a time. Please logout from the other device first or contact support if you believe this is an error.', 
              statusCode: 409,
              code: 'USER_ALREADY_LOGGED_IN',
              details: {
                existingDevice: existingSession.deviceInfo || 'Unknown Device',
                existingIp: existingSession.ipAddress || 'Unknown',
                existingLoginTime: existingSession.createdAt
              }
            }
          });
          return;
        }
      }

      const tokens = this.authService.generateTokens({
        id: user.id,
        email: user.email,
        role: user.role,
        isActive: user.isActive
      });

      // Create new session (this will invalidate all previous sessions)
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

      // Set cookies for tokens
      res.cookie('accessToken', tokens.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000 // 15 minutes
      });

      res.cookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      });

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
          }
        },
        message: 'Login successful. Previous sessions have been invalidated.'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Login failed',
          statusCode: 500
        }
      });
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
          'User logout - Single device session ended'
        );
      }

      // Clear cookies
      res.clearCookie('accessToken');
      res.clearCookie('refreshToken');

      const response: ApiResponse = {
        success: true,
        message: 'Logout successful. You can now login from another device.',
        data: {
          singleDeviceEnforced: true,
          message: 'Single device login is enforced. Only one device can be logged in at a time.'
        }
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
      const refreshToken = req.cookies.refreshToken;

      if (!refreshToken) {
        res.status(401).json({
          success: false,
          error: { message: 'Refresh token not found', statusCode: 401 }
        });
        return;
      }

      const tokens = await this.authService.refreshTokens(refreshToken);

      // Set new cookies
      res.cookie('accessToken', tokens.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000 // 15 minutes
      });

      res.cookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      });

      const response: ApiResponse = {
        success: true,
        message: 'Tokens refreshed successfully'
      };

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

      const response: ApiResponse = {
        success: true,
        message: 'Logged out from all devices successfully. You can now login from any device.',
        data: {
          singleDeviceEnforced: true,
          previousSessionsCount: currentSessions.length,
          message: 'Single device login is enforced. Only one device can be logged in at a time.'
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
          singleDeviceEnforced: true,
          activeSessions: activeSessions.length,
          currentSession: activeSessions.length > 0 ? {
            deviceInfo: activeSessions[0].deviceInfo,
            ipAddress: activeSessions[0].ipAddress,
            userAgent: activeSessions[0].userAgent,
            loginTime: activeSessions[0].createdAt,
            expiresAt: activeSessions[0].expiresAt
          } : null,
          message: 'Single device login is enforced. Only one device can be logged in at a time.'
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

      // Add single device enforcement info to logs
      const enhancedLogs = logs.map(log => ({
        ...log,
        singleDeviceEnforced: true,
        isLoginAttempt: log.reason?.includes('login') || log.reason?.includes('logout'),
        isSingleDeviceBlock: log.reason?.includes('already logged in on another device')
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
          },
          singleDeviceEnforced: true,
          message: 'Single device login is enforced. Only one device can be logged in at a time.'
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
        message: 'User has been force logged out from all devices successfully',
        data: {
          singleDeviceEnforced: true,
          message: 'Single device login is enforced. Only one device can be logged in at a time.'
        }
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

  // Google OAuth Callback
  @Get('/google/callback')
  async googleCallback(req: Request, res: Response, next: NextFunction): Promise<void> {
    console.log('🟡 [Backend Callback] Google OAuth callback received');
    console.log('🟡 [Backend Callback] Request URL:', req.url);
    console.log('🟡 [Backend Callback] Request query:', req.query);
    console.log('🟡 [Backend Callback] Session ID:', req.sessionID);
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

    console.log('🟡 [Backend Callback] Authenticating with Passport Google strategy...');
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
        console.log('🟡 [Backend Callback] Single device login enabled:', config.security.singleDeviceLogin);
        
        // Check if user already has an active session (Single Device Login Enforcement)
        if (config.security.singleDeviceLogin) {
          console.log('🟡 [Backend Callback] Checking for existing sessions...');
          const existingSessions = await this.authService.getUserSessions(user.id);
          console.log('🟡 [Backend Callback] Existing sessions count:', existingSessions.length);
          
          if (existingSessions.length > 0) {
            const existingSession = existingSessions[0];
            console.log('🟡 [Backend Callback] User already has active session:', {
              deviceInfo: existingSession.deviceInfo,
              ipAddress: existingSession.ipAddress,
            });
            
            await this.authService.logLoginAttempt(
              user.id,
              user.email,
              false,
              req.ip || '',
              req.get('User-Agent') || '',
              `User already logged in on another device. Existing session: ${existingSession.deviceInfo || 'Unknown Device'} (IP: ${existingSession.ipAddress || 'Unknown'})`
            );
            
            const errorUrl = `${config.frontendUrl}/signin?error=${encodeURIComponent('This account is already logged in on another device. Please logout from the other device first.')}`;
            console.log('🟡 [Backend Callback] Redirecting to:', errorUrl);
            return res.redirect(errorUrl);
          }
        }

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

        // Set cookies
        console.log('🟡 [Backend Callback] Setting cookies...');
        res.cookie('accessToken', tokens.accessToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax',
          maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });
        console.log('🟡 [Backend Callback] accessToken cookie set');

        if (tokens.refreshToken) {
          res.cookie('refreshToken', tokens.refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
          });
          console.log('🟡 [Backend Callback] refreshToken cookie set');
        }

        // Get redirect URL from session or default to dashboard
        const redirectUrl = (req.session as any)?.redirectUrl || '/dashboard';
        delete (req.session as any)?.redirectUrl;
        console.log('🟡 [Backend Callback] Redirect URL from session:', redirectUrl);
        console.log('🟡 [Backend Callback] Frontend URL:', config.frontendUrl);

        const finalRedirectUrl = `${config.frontendUrl}${redirectUrl}`;
        console.log('🟡 [Backend Callback] Final redirect URL:', finalRedirectUrl);
        console.log('🟡 [Backend Callback] Redirecting to frontend...');

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
}