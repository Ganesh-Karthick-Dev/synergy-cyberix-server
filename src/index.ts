import 'reflect-metadata';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import session from 'express-session';
import passport from 'passport';
import { config } from './config/env.config';

// Global BigInt serializer for JSON.stringify
// This ensures BigInt values are converted to strings when serializing JSON
(BigInt.prototype as any).toJSON = function() {
  return this.toString();
};
// Import passport config to register strategies
import './config/passport';
import { errorHandler } from './middlewares/error.middleware';
import { notFoundHandler } from './middlewares/not-found.middleware';
import { RouteFactory } from './factories/route.factory';
import { container } from './container/container';
import { RegistrationController } from './modules/controllers/registration.controller';
import { AuthController } from './modules/controllers/auth.controller';
import { AdminController } from './modules/controllers/admin.controller';
import { DashboardController } from './modules/controllers/dashboard.controller';
import { UsersController } from './modules/controllers/users.controller';
import { PlanController } from './modules/controllers/plan.controller';
import { SecurityToolsController } from './modules/controllers/security-tools.controller';
import { PushNotificationController } from './modules/controllers/push-notification.controller';
import { NotificationsController } from './modules/controllers/notifications.controller';
import { AdsController } from './modules/controllers/ads.controller';
import { FcmController } from './modules/controllers/fcm.controller';
import { GitHubController } from './modules/controllers/github.controller';
import { PaymentController } from './modules/controllers/payment.controller';
import { ProjectController } from './modules/controllers/project.controller';
import { SecurityReportController } from './modules/controllers/security-report.controller';
import { ContactController } from './modules/controllers/contact.controller';
import { ChatController } from './modules/controllers/chat.controller';
import { InvoiceService } from './modules/services/invoice.service';
import { PlanRestrictionService } from './modules/services/plan-restriction.service';
import { ProjectService } from './modules/services/project.service';
import { SecurityReportService } from './modules/services/security-report.service';
import { PushNotificationService } from './modules/services/push-notification.service';
import { UserService } from './modules/services/user.service';
import { EmailService } from './modules/services/email.service';
import { AuthService } from './modules/services/auth.service';
import { startCleanupScheduler } from './utils/cleanup';
import { getWelcomeBannerHTML } from './utils/welcome-banner';

class Server {
  private app: express.Application;
  private port: number;

  constructor() {
    this.app = express();
    this.port = config.port;
    this.initializeMiddlewares();
    this.initializeRoutes();
    this.initializeErrorHandling();
  }

  private initializeMiddlewares(): void {
    // Security middleware
    this.app.use(helmet());
    
    // CORS configuration - allow all origins for simplicity
    this.app.use(cors({
      origin: true, // Allow all origins
      credentials: true, // Required for cookies
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'X-Requested-With', 'Authorization', 'Cookie'],
      exposedHeaders: ['Set-Cookie'],
      preflightContinue: false,
      optionsSuccessStatus: 204
    }));

    // Rate limiting
    const limiter = rateLimit({
      windowMs: config.rateLimit.windowMs,
      max: config.rateLimit.maxRequests,
      message: {
        error: 'Too many requests from this IP, please try again later.'
      },
      standardHeaders: true,
      legacyHeaders: false
    });
    this.app.use(limiter);

    // Body parsing middleware
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));
    this.app.use(cookieParser());

    // Session configuration (required for Passport OAuth)
    this.app.use(session({
      secret: config.session.secret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
      }
    }));

    // Initialize Passport
    this.app.use(passport.initialize());
    this.app.use(passport.session());

    // Compression middleware
    this.app.use(compression());

    // Logging middleware
      this.app.use(morgan('combined'));
  }

  private initializeRoutes(): void {
    // Welcome banner route - must be before API routes
    this.app.get('/', (req, res) => {
      res.send(getWelcomeBannerHTML());
    });

    // Register services in container
    container.autoRegister(EmailService);
    container.autoRegister(AuthService);
    container.autoRegister(UserService);
    container.autoRegister(InvoiceService);
    container.autoRegister(PlanRestrictionService);
    container.autoRegister(ProjectService);
    container.autoRegister(SecurityReportService);
    container.autoRegister(PushNotificationService);
    container.autoRegister(RegistrationController);
    container.autoRegister(AuthController);
    container.autoRegister(AdminController);
    container.autoRegister(DashboardController);
    container.autoRegister(UsersController);
    container.autoRegister(PlanController);
    container.autoRegister(SecurityToolsController);
    container.autoRegister(PushNotificationController);
    container.autoRegister(NotificationsController);
    container.autoRegister(AdsController);
    container.autoRegister(FcmController);
    container.autoRegister(GitHubController);
    container.autoRegister(PaymentController);
    container.autoRegister(ProjectController);
    container.autoRegister(SecurityReportController);
    container.autoRegister(ContactController);
    container.autoRegister(ChatController);

    // Health check endpoints (both /health and /api/health for compatibility)
    const healthCheckHandler = (req: express.Request, res: express.Response) => {
      res.status(200).json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: config.nodeEnv
      });
    };
    
    this.app.get('/health', healthCheckHandler);
    this.app.get('/api/health', healthCheckHandler);

    // API routes using decorators
    const apiRoutes = RouteFactory.createRoutes([
      RegistrationController,
      AuthController,
      AdminController,
      DashboardController,
      UsersController,
      PlanController,
      PaymentController,
      ProjectController,
      SecurityReportController,
      SecurityToolsController,
      PushNotificationController,
      NotificationsController,
      AdsController,
      GitHubController,
      ChatController,
      ContactController
    ]);
    this.app.use('/', apiRoutes);
  }

  private initializeErrorHandling(): void {
    // 404 handler
    this.app.use(notFoundHandler);
    
    // Global error handler
    this.app.use(errorHandler);
  }

  public start(): void {
    this.app.listen(this.port, '0.0.0.0', () => {
      console.log(`🚀 Server is running on port ${this.port}`);
      console.log(`📊 Environment: ${config.nodeEnv}`);
      console.log(`🔗 Health check: http://localhost:${this.port}/health`);
      console.log(`📖 API Documentation: http://localhost:${this.port}/api`);
      
      // Start cleanup scheduler
      startCleanupScheduler();
    });
  }
}

// Start the server
const server = new Server();
server.start();

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  process.exit(0);
});

export default Server;
