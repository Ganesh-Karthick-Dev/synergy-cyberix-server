import dotenv from 'dotenv';
import path from 'path';

// Load environment variables - production mode only
dotenv.config(); // Load .env file

interface Config {
  port: number;
  nodeEnv: string;
  security: {
    loginBlocking: boolean;
    emailNotifications: boolean;
    adminAccessControl: boolean;
  };
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
  google?: {
    clientId: string;
    clientSecret: string;
    callbackURL: string;
  };
  github?: {
    clientId: string;
    clientSecret: string;
    callbackURL: string;
  };
  frontendUrl: string;
  razorpay?: {
    keyId: string;
    keySecret: string;
  };
}

const config: Config = {
  port: parseInt(process.env.PORT || '8000', 10),
  nodeEnv: process.env.NODE_ENV || 'production',
  security: {
    loginBlocking: process.env.LOGIN_BLOCKING !== 'false',
    emailNotifications: process.env.EMAIL_NOTIFICATIONS !== 'false',
    adminAccessControl: process.env.ADMIN_ACCESS_CONTROL !== 'false'
  },
  
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
    origin: process.env.CORS_ORIGIN || ['http://localhost:3000', 'http://localhost:3001']
  },
  
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 minutes
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10)
  },
  
  upload: {
    maxFileSize: parseInt(process.env.MAX_FILE_SIZE || '10485760', 10), // 10MB
    path: process.env.UPLOAD_PATH || './uploads'
  },
  frontendUrl: process.env.FRONTEND_URL || 'http://localhost:3000'
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

// Add Google OAuth configuration if provided
const googleClientId = process.env.GOOGLE_CLIENT_ID?.trim();
const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET?.trim();

if (googleClientId && googleClientSecret && googleClientId.length > 0 && googleClientSecret.length > 0) {
  // Google callback URL: Can point to frontend Next.js API route (which proxies to backend)
  // OR directly to backend. Must match Google Console's "Authorized redirect URIs"
  // Default: Use GOOGLE_CALLBACK_URL from .env, or construct backend URL
  const backendUrl = process.env.BACKEND_URL || `http://localhost:${config.port}`;
  const callbackUrl = process.env.GOOGLE_CALLBACK_URL?.trim() || `${backendUrl}/api/auth/google/callback`;
  
  config.google = {
    clientId: googleClientId,
    clientSecret: googleClientSecret,
    callbackURL: callbackUrl
  };
  
  // Log configuration status (only client ID prefix for security)
  console.log('✅ Google OAuth configured');
  console.log('   Callback URL:', callbackUrl);
} else {
  // Log missing configuration
  console.warn('⚠️  Google OAuth not configured.');
  console.warn('   GOOGLE_CLIENT_ID:', googleClientId ? `${googleClientId.substring(0, 20)}...` : 'not set');
  console.warn('   GOOGLE_CLIENT_SECRET:', googleClientSecret ? 'set' : 'not set');
}

// Add GitHub OAuth configuration if provided
const githubClientId = process.env.GITHUB_CLIENT_ID?.trim();
const githubClientSecret = process.env.GITHUB_CLIENT_SECRET?.trim();

if (githubClientId && githubClientSecret && githubClientId.length > 0 && githubClientSecret.length > 0) {
  const backendUrl = process.env.BACKEND_URL || `http://localhost:${config.port}`;
  // Use /api/auth/github/callback for web OAuth (not /api/github/callback)
  const callbackUrl = process.env.GITHUB_CALLBACK_URL?.trim() || `${backendUrl}/api/auth/github/callback`;
  
  config.github = {
    clientId: githubClientId,
    clientSecret: githubClientSecret,
    callbackURL: callbackUrl
  };
  
  // Log configuration status (only client ID prefix for security)
  console.log('✅ GitHub OAuth configured');
  console.log('   Callback URL:', callbackUrl);
  console.log('   ⚠️  Make sure this URL is registered in your GitHub OAuth App settings!');
} else {
  // Log missing configuration
  console.warn('⚠️  GitHub OAuth not configured.');
  console.warn('   GITHUB_CLIENT_ID:', githubClientId ? `${githubClientId.substring(0, 20)}...` : 'not set');
  console.warn('   GITHUB_CLIENT_SECRET:', githubClientSecret ? 'set' : 'not set');
}

// Add Razorpay configuration if provided
const razorpayKeyId = process.env.RAZORPAY_KEY_ID?.trim();
const razorpayKeySecret = process.env.RAZORPAY_KEY_SECRET?.trim();

if (razorpayKeyId && razorpayKeySecret && razorpayKeyId.length > 0 && razorpayKeySecret.length > 0) {
  config.razorpay = {
    keyId: razorpayKeyId,
    keySecret: razorpayKeySecret
  };

  console.log('✅ Razorpay payment gateway configured');
} else {
  console.warn('⚠️  Razorpay not configured.');
  console.warn('   RAZORPAY_KEY_ID:', razorpayKeyId ? 'set' : 'not set');
  console.warn('   RAZORPAY_KEY_SECRET:', razorpayKeySecret ? 'set' : 'not set');
}

export { config };
