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
import { NotificationsController } from './modules/controllers/notifications.controller';
import { AdsController } from './modules/controllers/ads.controller';
import { UserService } from './modules/services/user.service';
import { EmailService } from './modules/services/email.service';
import { AuthService } from './modules/services/auth.service';
import { startCleanupScheduler } from './utils/cleanup';

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
      allowedHeaders: ['Content-Type', 'X-Requested-With'],
      exposedHeaders: ['Set-Cookie']
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
    // Register services in container
    container.autoRegister(EmailService);
    container.autoRegister(AuthService);
    container.autoRegister(UserService);
    container.autoRegister(RegistrationController);
    container.autoRegister(AuthController);
    container.autoRegister(AdminController);
    container.autoRegister(DashboardController);
    container.autoRegister(UsersController);
    container.autoRegister(PlanController);
    container.autoRegister(SecurityToolsController);
    container.autoRegister(NotificationsController);
    container.autoRegister(AdsController);

    // Health check endpoint
    this.app.get('/health', (req, res) => {
      res.status(200).json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: config.nodeEnv
      });
    });

    // API routes using decorators
    const apiRoutes = RouteFactory.createRoutes([
      RegistrationController,
      AuthController,
      AdminController,
      DashboardController,
      UsersController,
      PlanController,
      SecurityToolsController,
      NotificationsController,
      AdsController
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
    this.app.listen(this.port, () => {
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
