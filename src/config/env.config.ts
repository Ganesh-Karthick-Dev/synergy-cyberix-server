import dotenv from 'dotenv';
import path from 'path';

// Load environment variables based on NODE_ENV
const nodeEnv = process.env.NODE_ENV || 'development';
const envFile = nodeEnv === 'production' ? '.env.production' : '.env.development';

// Try to load specific env file, fallback to .env
try {
  dotenv.config({ path: path.resolve(process.cwd(), envFile) });
} catch (error) {
  // Fallback to default .env file
  dotenv.config();
}

interface Config {
  port: number;
  nodeEnv: string;
  database: {
    url: string;
  };
  jwt: {
    secret: string;
    expiresIn: string;
    refreshSecret: string;
    refreshExpiresIn: string;
  };
  session: {
    secret: string;
  };
  cors: {
    origin: string | string[];
  };
  rateLimit: {
    windowMs: number;
    maxRequests: number;
  };
  email?: {
    host: string;
    port: number;
    user: string;
    pass: string;
  };
  upload: {
    maxFileSize: number;
    path: string;
  };
}

const config: Config = {
  port: parseInt(process.env.PORT || '3000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  
  database: {
    url: process.env.DATABASE_URL || (() => {
      const host = process.env.DB_HOST || 'localhost';
      const port = process.env.DB_PORT || '5432';
      const username = process.env.DB_USERNAME || 'postgres';
      const password = process.env.DB_PASSWORD || '12345';
      const database = process.env.DB_NAME || 'cyberix';
      return `postgresql://${username}:${password}@${host}:${port}/${database}?schema=public`;
    })()
  },
  
  jwt: {
    secret: process.env.JWT_SECRET || 'your-super-secret-jwt-key-here',
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
    refreshSecret: process.env.JWT_REFRESH_SECRET || 'your-super-secret-refresh-key-here',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '30d'
  },
  
  session: {
    secret: process.env.SESSION_SECRET || 'your-super-secret-session-key-here'
  },
  
  cors: {
    origin: process.env.CORS_ORIGIN || 'http://localhost:3000'
  },
  
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 minutes
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10)
  },
  
  upload: {
    maxFileSize: parseInt(process.env.MAX_FILE_SIZE || '10485760', 10), // 10MB
    path: process.env.UPLOAD_PATH || './uploads'
  }
};

// Add email configuration if provided
if (process.env.SMTP_HOST && process.env.SMTP_USER) {
  config.email = {
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587', 10),
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS || ''
  };
} else {
  // Default Gmail configuration
  config.email = {
    host: 'smtp.gmail.com',
    port: 587,
    user: 'ganeshkarthik18697@gmail.com',
    pass: 'wvrf mwak wlmk eevx'
  };
}

export { config };
