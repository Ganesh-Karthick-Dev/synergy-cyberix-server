import { Request, Response, NextFunction } from 'express';
import passport from 'passport';
import { CustomError } from './error.middleware';
import { AuthService } from '../modules/services/auth.service';

// Extend Request interface to include user
declare global {
  namespace Express {
    interface User {
      id: string;
      email: string;
      role: string;
      isActive: boolean;
    }
  }
}

export const authenticate = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  // Check for access token in cookies first, then Authorization header as fallback
  let accessToken = req.cookies.accessToken;
  let tokenSource = 'cookie'; // Track where token came from
  
  // If no cookie, check Authorization header
  if (!accessToken) {
    const authHeader = req.get('authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
      accessToken = authHeader.substring(7);
      tokenSource = 'header';
      console.log('🔐 [Auth Middleware] Using token from Authorization header');
    }
  }
  
  // Debug logging - very detailed
  console.log('🔐 [Auth Middleware] ===== AUTHENTICATION CHECK START =====');
  console.log('🔐 [Auth Middleware] Token source:', tokenSource);
  console.log('🔐 [Auth Middleware] Request details:', {
    url: req.url,
    method: req.method,
    origin: req.get('origin'),
    referer: req.get('referer'),
    host: req.get('host'),
  });
  
  console.log('🔐 [Auth Middleware] All cookies received:', {
    cookieCount: Object.keys(req.cookies).length,
    cookieNames: Object.keys(req.cookies),
    hasAccessToken: !!req.cookies.accessToken,
    hasRefreshToken: !!req.cookies.refreshToken,
    accessTokenLength: req.cookies.accessToken?.length || 0,
    refreshTokenLength: req.cookies.refreshToken?.length || 0,
    accessTokenPreview: req.cookies.accessToken ? req.cookies.accessToken.substring(0, 30) + '...' : 'MISSING',
  });
  
  // Also check raw cookie header
  const rawCookieHeader = req.get('cookie');
  console.log('🔐 [Auth Middleware] Raw Cookie header:', {
    present: !!rawCookieHeader,
    headerValue: rawCookieHeader ? rawCookieHeader.substring(0, 200) : 'MISSING',
  });
  
  // Check Authorization header
  const authHeader = req.get('authorization');
  console.log('🔐 [Auth Middleware] Authorization header:', {
    present: !!authHeader,
    hasBearer: authHeader?.startsWith('Bearer ') || false,
    preview: authHeader ? authHeader.substring(0, 50) + '...' : 'MISSING',
  });
  
  if (!accessToken) {
    console.log('❌ [Auth Middleware] ===== AUTHENTICATION FAILED: No accessToken found =====');
    console.log('❌ [Auth Middleware] Available cookies:', Object.keys(req.cookies));
    console.log('❌ [Auth Middleware] Authorization header:', authHeader ? 'Present' : 'Missing');
    return next(new CustomError('Authentication required', 401));
  }

  try {
    // If token is from Authorization header, verify JWT directly (skip session check)
    // If token is from cookie, validate session in database
    if (tokenSource === 'header') {
      console.log('🔐 [Auth Middleware] Token from Authorization header - verifying JWT directly');
      
      // Add token to Authorization header for passport
      req.headers.authorization = `Bearer ${accessToken}`;

      // Verify JWT directly with Passport (no session check needed for JWT)
      passport.authenticate('jwt', { session: false }, (err: any, user: any, info: any) => {
        if (err) {
          console.error('❌ [Auth Middleware] JWT verification error:', err);
          return next(new CustomError('Authentication error', 500));
        }

        if (!user) {
          console.log('❌ [Auth Middleware] ===== AUTHENTICATION FAILED: JWT invalid or expired =====');
          console.log('❌ [Auth Middleware] JWT info:', info);
          return next(new CustomError('Token invalid or expired. Please login again.', 401));
        }

        console.log('✅ [Auth Middleware] ===== AUTHENTICATION SUCCESS (JWT) =====');
        console.log('✅ [Auth Middleware] Authenticated user:', {
          id: user.id,
          email: user.email,
          role: user.role,
          isActive: user.isActive,
        });
        req.user = user;
        next();
      })(req, res, next);
    } else {
      // Token from cookie - validate session in database
      console.log('🔐 [Auth Middleware] Token from cookie - validating session in database...');
      const authService = new AuthService();
      const isSessionValid = await authService.validateSession(accessToken);
      
      console.log('🔐 [Auth Middleware] Session validation result:', {
        isSessionValid,
        accessTokenLength: accessToken?.length || 0,
        tokenPreview: accessToken.substring(0, 30) + '...',
      });
      
      if (!isSessionValid) {
        console.log('❌ [Auth Middleware] ===== AUTHENTICATION FAILED: Session invalid/expired =====');
        return next(new CustomError('Session expired or invalid. Please login again.', 401));
      }

      // Add token to Authorization header for passport
      req.headers.authorization = `Bearer ${accessToken}`;

      passport.authenticate('jwt', { session: false }, (err: any, user: any, info: any) => {
        if (err) {
          return next(new CustomError('Authentication error', 500));
        }

        if (!user) {
          console.log('❌ [Auth Middleware] ===== AUTHENTICATION FAILED: Passport returned no user =====');
          return next(new CustomError('Authentication required', 401));
        }

        console.log('✅ [Auth Middleware] ===== AUTHENTICATION SUCCESS (Session) =====');
        console.log('✅ [Auth Middleware] Authenticated user:', {
          id: user.id,
          email: user.email,
          role: user.role,
          isActive: user.isActive,
        });
        req.user = user;
        next();
      })(req, res, next);
    }
  } catch (error) {
    console.error('❌ [Auth Middleware] Authentication error:', error);
    return next(new CustomError('Authentication error', 500));
  }
};

export const authorize = (...roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      return next(new CustomError('Authentication required', 401));
    }

    if (!roles.includes(req.user.role)) {
      return next(new CustomError('Insufficient permissions', 403));
    }

    next();
  };
};

export const optionalAuth = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  // Check for access token in cookies first
  const accessToken = req.cookies.accessToken;
  
  if (!accessToken) {
    req.user = undefined;
    return next();
  }

  try {
    // Validate session exists and is active
    const authService = new AuthService();
    const isSessionValid = await authService.validateSession(accessToken);
    
    if (!isSessionValid) {
      req.user = undefined;
      return next();
    }

    // Add token to Authorization header for passport
    req.headers.authorization = `Bearer ${accessToken}`;

    passport.authenticate('jwt', { session: false }, (err: any, user: any) => {
      if (err) {
        return next(new CustomError('Authentication error', 500));
      }

      req.user = user || undefined;
      next();
    })(req, res, next);
  } catch (error) {
    req.user = undefined;
    next();
  }
};
