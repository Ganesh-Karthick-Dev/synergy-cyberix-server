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
          { email: email }
        ]
      }
    });

    if (existingUser) {
      throw new CustomError('User with this email already exists', 400);
    }

    // Generate password
    const password = generateRandomPassword(12);

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Use database transaction to ensure atomicity
    const result = await prisma.$transaction(async (tx) => {
      try {
        // Create user - ONLY regular users can register, never admins
        const user = await tx.user.create({
          data: {
            email: email,
            username: null, // No username concept
            password: hashedPassword,
            firstName,
            lastName,
            phone,
            role: 'USER', // Always USER role for registrations
            status: 'ACTIVE'
          },
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            phone: true,
            role: true,
            status: true,
            createdAt: true,
            updatedAt: true
          }
        });

        // Create subscription for the user within the same transaction
        await this.createUserSubscriptionInTransaction(tx, user.id, subscriptionType);

        return user;
      } catch (error) {
        logger.error('Transaction failed during user registration:', error);
        throw error; // This will automatically rollback the transaction
      }
    });

    // Send welcome email (outside transaction - if this fails, user is still created)
    try {
      await this.emailService.sendRegistrationEmail(
        result.email,
        result.firstName || 'User',
        result.email, // Use email instead of username
        password
      );
    } catch (error) {
      logger.error('Failed to send registration email:', error);
      // Don't fail registration if email fails - user is already created
    }

    // Log user registration
    logger.info('User registered successfully', { 
      userId: result.id, 
      email: result.email,
      subscriptionType 
    });

    return {
      id: result.id,
      email: result.email,
      firstName: result.firstName,
      lastName: result.lastName,
      phone: result.phone,
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

  private async createUserSubscriptionInTransaction(tx: any, userId: string, subscriptionType: string) {
    // Find the service plan within the transaction
    const servicePlan = await tx.servicePlan.findFirst({
      where: { name: subscriptionType }
    });

    if (!servicePlan) {
      throw new CustomError('Service plan not found', 400);
    }

    // Create user subscription within the transaction
    await tx.userSubscription.create({
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
    const { email, password, firstName, lastName, phone } = userData;

    // Check if user already exists
    const existingUser = await prisma.user.findFirst({
      where: {
        email: email
      }
    });

    if (existingUser) {
      throw new CustomError('User with this email already exists', 400);
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user - ONLY regular users can be created through this method
    const user = await prisma.user.create({
      data: {
        email: email,
        username: null, // No username concept
        password: hashedPassword,
        firstName,
        lastName,
        phone,
        role: 'USER', // Always USER role - admins must be created manually
        status: 'ACTIVE'
      },
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

    // Log user creation
    logger.info('User created successfully', { userId: user.id, email: user.email });

    // SECURITY: Only authorized admin emails can have ADMIN role, all others are USER
    const adminEmails = ['webnox@admin.com', 'webnox1@admin.com'];
    const finalRole = adminEmails.includes(user.email) ? 'ADMIN' : 'USER';
    
    // Return user in UserPayload format
    return {
      id: user.id,
      email: user.email,
      role: finalRole, // Force role based on email, not database
      isActive: user.status === 'ACTIVE'
    };
  }

  async getUserById(id: string) {
    const user = await prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
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
      where: { email: email }
    });

    return user;
  }

  async updateUser(id: string, userData: UpdateUserDto) {
    const { email, password } = userData;

    // Check if email already exists (excluding current user)
    if (email) {
      const existingUser = await prisma.user.findFirst({
        where: {
          AND: [
            { id: { not: id } },
            { email: email }
          ]
        }
      });

      if (existingUser) {
        throw new CustomError('User with this email already exists', 400);
      }
    }

    // Prepare update data
    const updateData: any = {};
    if (email) updateData.email = email;
    if (password) updateData.password = await bcrypt.hash(password, 12);

    const user = await prisma.user.update({
      where: { id },
      data: updateData,
      select: {
        id: true,
        email: true,
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
      email: { contains: search, mode: 'insensitive' as const }
    } : {};

    const [users, total] = await Promise.all([
      prisma.user.findMany({
        where,
        skip,
        take: limit,
        select: {
          id: true,
          email: true,
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

    if (!user) {
      await this.logLoginAttempt(email, false, ipAddress, userAgent, 'User not found');
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

    // SECURITY: Only authorized admin emails can have ADMIN role, all others are USER
    const adminEmails = ['webnox@admin.com', 'webnox1@admin.com'];
    const finalRole = adminEmails.includes(user.email) ? 'ADMIN' : 'USER';
    
    return {
      id: user.id,
      email: user.email,
      role: finalRole, // Force role based on email, not database
      isActive: user.status === 'ACTIVE'
    };
  }

  async logLoginAttempt(email: string, success: boolean, ipAddress?: string, userAgent?: string, reason?: string) {
    // Simplified logging - just log to console for now
    logger.info('Login attempt', { email, success, ipAddress, userAgent, reason });
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

  /**
   * Create admin user - ONLY for the specific webnox@admin.com admin
   * This method should only be used during seeding or by super admin
   */
  async createAdminUser(adminData: {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
    phone?: string;
  }): Promise<any> {
    const { email, password, firstName, lastName, phone } = adminData;

    // Only allow creation of the specific admin email
    if (email !== 'webnox@admin.com') {
      throw new CustomError('Only webnox@admin.com can be created as admin', 403);
    }

    // Check if admin already exists
    const existingAdmin = await prisma.user.findFirst({
      where: { 
        OR: [
          { email: 'webnox@admin.com' },
          { role: 'ADMIN' }
        ]
      }
    });

    if (existingAdmin) {
      throw new CustomError('Admin user already exists', 400);
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create admin user
    const admin = await prisma.user.create({
      data: {
        email: email,
        username: 'webnox_admin',
        password: hashedPassword,
        firstName,
        lastName,
        phone,
        role: 'ADMIN',
        status: 'ACTIVE',
        emailVerified: true,
        twoFactorEnabled: false
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        phone: true,
        role: true,
        status: true,
        emailVerified: true,
        twoFactorEnabled: true,
        lastLoginAt: true,
        createdAt: true,
        updatedAt: true
      }
    });

    logger.info('Admin user created successfully', { 
      adminId: admin.id, 
      email: admin.email 
    });

    return admin;
  }

  /**
   * Validate admin access - only webnox@admin.com can access admin features
   */
  validateAdminAccess(email: string, role: string): boolean {
    if (role === 'ADMIN' && email !== 'webnox@admin.com') {
      return false;
    }
    return true;
  }
}
