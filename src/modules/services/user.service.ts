import { prisma } from '../../config/db';
import bcrypt from 'bcryptjs';
import { CreateUserDto, UpdateUserDto, LoginDto, ChangePasswordDto, ForgotPasswordDto, ResetPasswordDto, RegisterUserDto } from '../dtos/user.dto';
import { CustomError } from '../../middlewares/error.middleware';
import { UserPayload } from '../../types';
import { logger } from '../../utils/logger';
import { generateRandomPassword, generateUsernameFromEmail } from '../../utils/password.utils';
import { EmailService } from './email.service';
import { Service, Inject } from '../../decorators/service.decorator';

@Service()
export class UserService {
  private emailService: EmailService;

  constructor() {
    this.emailService = new EmailService();
  }

  async registerUser(registerData: RegisterUserDto) {
    const { email, firstName, lastName, phone, subscriptionType = 'FREE' } = registerData;

    // Check if user already exists
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [
          { email: email.toLowerCase() }
        ]
      }
    });

    if (existingUser) {
      throw new CustomError('User with this email already exists', 400);
    }

    // Generate username and password
    const username = generateUsernameFromEmail(email);
    const password = generateRandomPassword(12);

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const user = await prisma.user.create({
      data: {
        email: email.toLowerCase(),
        username: username.toLowerCase(),
        password: hashedPassword,
        firstName,
        lastName,
        phone,
        role: 'USER',
        status: 'ACTIVE'
      },
      select: {
        id: true,
        email: true,
        username: true,
        firstName: true,
        lastName: true,
        phone: true,
        role: true,
        status: true,
        createdAt: true,
        updatedAt: true
      }
    });

    // Create subscription for the user
    await this.createUserSubscription(user.id, subscriptionType);

    // Send welcome email
    try {
      await this.emailService.sendRegistrationEmail(
        user.email,
        user.firstName || 'User',
        user.username,
        password
      );
    } catch (error) {
      logger.error('Failed to send registration email:', error);
      // Don't fail registration if email fails
    }

    // Log user registration
    logger.info('User registered successfully', { 
      userId: user.id, 
      email: user.email,
      subscriptionType 
    });

    return {
      id: user.id,
      email: user.email,
      username: user.username,
      firstName: user.firstName,
      lastName: user.lastName,
      phone: user.phone,
      subscriptionType,
      message: 'Registration successful. Please check your email for login credentials.'
    };
  }

  private async createUserSubscription(userId: string, subscriptionType: string) {
    // Find the service plan
    const servicePlan = await prisma.servicePlan.findFirst({
      where: { name: subscriptionType }
    });

    if (!servicePlan) {
      throw new CustomError('Service plan not found', 400);
    }

    // Create user subscription
    await prisma.userSubscription.create({
      data: {
        userId,
        planId: servicePlan.id,
        status: 'ACTIVE',
        startDate: new Date(),
        autoRenew: true
      }
    });
  }

  async createUser(userData: CreateUserDto) {
    const { email, username, password, firstName, lastName, phone } = userData;

    // Check if user already exists
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [
          { email: email.toLowerCase() },
          { username: username.toLowerCase() }
        ]
      }
    });

    if (existingUser) {
      if (existingUser.email === email.toLowerCase()) {
        throw new CustomError('Email already exists', 400);
      }
      if (existingUser.username === username.toLowerCase()) {
        throw new CustomError('Username already exists', 400);
      }
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const user = await prisma.user.create({
      data: {
        email: email.toLowerCase(),
        username: username.toLowerCase(),
        password: hashedPassword,
        firstName,
        lastName,
        phone,
        role: 'USER',
        status: 'ACTIVE'
      },
      select: {
        id: true,
        email: true,
        username: true,
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

    // Log user creation
    logger.info('User created successfully', { userId: user.id, email: user.email });

    // Return user in UserPayload format
    return {
      id: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
      isActive: user.status === 'ACTIVE'
    };
  }

  async getUserById(id: string) {
    const user = await prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        username: true,
        role: true,
        status: true,
        createdAt: true,
        updatedAt: true
      }
    });

    if (!user) {
      throw new CustomError('User not found', 404);
    }

    return user;
  }

  async getUserByEmail(email: string) {
    const user = await prisma.user.findUnique({
      where: { email: email.toLowerCase() }
    });

    return user;
  }

  async updateUser(id: string, userData: UpdateUserDto) {
    const { email, username, password } = userData;

    // Check if email or username already exists (excluding current user)
    if (email || username) {
      const existingUser = await prisma.user.findFirst({
        where: {
          AND: [
            { id: { not: id } },
            {
              OR: [
                ...(email ? [{ email: email.toLowerCase() }] : []),
                ...(username ? [{ username: username.toLowerCase() }] : [])
              ]
            }
          ]
        }
      });

      if (existingUser) {
        if (existingUser.email === email?.toLowerCase()) {
          throw new CustomError('Email already exists', 400);
        }
        if (existingUser.username === username?.toLowerCase()) {
          throw new CustomError('Username already exists', 400);
        }
      }
    }

    // Prepare update data
    const updateData: any = {};
    if (email) updateData.email = email.toLowerCase();
    if (username) updateData.username = username.toLowerCase();
    if (password) updateData.password = await bcrypt.hash(password, 12);

    const user = await prisma.user.update({
      where: { id },
      data: updateData,
      select: {
        id: true,
        email: true,
        username: true,
        role: true,
        status: true,
        createdAt: true,
        updatedAt: true
      }
    });

    return user;
  }

  async deleteUser(id: string) {
    const user = await prisma.user.delete({
      where: { id }
    });

    return user;
  }

  async getAllUsers(page: number = 1, limit: number = 10, search?: string) {
    const skip = (page - 1) * limit;

    const where = search ? {
      OR: [
        { email: { contains: search, mode: 'insensitive' as const } },
        { username: { contains: search, mode: 'insensitive' as const } }
      ]
    } : {};

    const [users, total] = await Promise.all([
      prisma.user.findMany({
        where,
        skip,
        take: limit,
        select: {
          id: true,
          email: true,
          username: true,
          role: true,
          status: true,
          createdAt: true,
          updatedAt: true
        },
        orderBy: { createdAt: 'desc' }
      }),
      prisma.user.count({ where })
    ]);

    return {
      users,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
      }
    };
  }

  async validateCredentials(credentials: LoginDto, ipAddress?: string, userAgent?: string): Promise<UserPayload> {
    const { email, password, deviceInfo } = credentials;

    const user = await this.getUserByEmail(email);
    
    // Log login attempt
    await this.logLoginAttempt(email, false, ipAddress, userAgent, 'User not found');

    if (!user) {
      throw new CustomError('Invalid credentials', 401);
    }

    if (user.status !== 'ACTIVE') {
      await this.logLoginAttempt(email, false, ipAddress, userAgent, 'Account not active');
      throw new CustomError('Account is not active', 401);
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      await this.logLoginAttempt(email, false, ipAddress, userAgent, 'Invalid password');
      throw new CustomError('Invalid credentials', 401);
    }

    // Update last login
    await prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() }
    });

    // Log successful login
    await this.logLoginAttempt(email, true, ipAddress, userAgent);

    logger.info('User logged in successfully', { 
      userId: user.id, 
      email: user.email, 
      ipAddress, 
      deviceInfo 
    });

    return {
      id: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
      isActive: user.status === 'ACTIVE'
    };
  }

  async logLoginAttempt(email: string, success: boolean, ipAddress?: string, userAgent?: string, reason?: string) {
    try {
      await prisma.loginLog.create({
        data: {
          userId: success ? (await this.getUserByEmail(email))?.id || '' : '',
          email,
          success,
          ipAddress,
          userAgent,
          reason
        }
      });
    } catch (error) {
      logger.error('Failed to log login attempt', { error, email, success });
    }
  }

  async createSession(userId: string, token: string, expiresAt: Date, deviceInfo?: string, ipAddress?: string, userAgent?: string) {
    return await prisma.session.create({
      data: {
        userId,
        token,
        expiresAt,
        deviceInfo,
        ipAddress,
        userAgent
      }
    });
  }

  async getActiveSessions(userId: string) {
    return await prisma.session.findMany({
      where: {
        userId,
        expiresAt: { gt: new Date() }
      },
      orderBy: { createdAt: 'desc' }
    });
  }

  async revokeSession(sessionId: string, userId: string) {
    const session = await prisma.session.findFirst({
      where: { id: sessionId, userId }
    });

    if (!session) {
      throw new CustomError('Session not found', 404);
    }

    await prisma.session.delete({
      where: { id: sessionId }
    });

    logger.info('Session revoked', { sessionId, userId });
  }

  async revokeAllSessions(userId: string) {
    await prisma.session.deleteMany({
      where: { userId }
    });

    logger.info('All sessions revoked', { userId });
  }

  async changePassword(userId: string, changePasswordData: ChangePasswordDto) {
    const { currentPassword, newPassword } = changePasswordData;

    const user = await prisma.user.findUnique({
      where: { id: userId }
    });

    if (!user) {
      throw new CustomError('User not found', 404);
    }

    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isCurrentPasswordValid) {
      throw new CustomError('Current password is incorrect', 400);
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 12);

    await prisma.user.update({
      where: { id: userId },
      data: { password: hashedNewPassword }
    });

    return { message: 'Password changed successfully' };
  }
}
