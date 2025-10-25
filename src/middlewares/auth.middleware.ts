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
  // Check for access token in cookies first
  const accessToken = req.cookies.accessToken;
  
  if (!accessToken) {
    return next(new CustomError('Authentication required', 401));
  }

  try {
    // Validate session exists and is active
    const authService = new AuthService();
    const isSessionValid = await authService.validateSession(accessToken);
    
    if (!isSessionValid) {
      return next(new CustomError('Session expired or invalid. Please login again.', 401));
    }

    // Add token to Authorization header for passport
    req.headers.authorization = `Bearer ${accessToken}`;

    passport.authenticate('jwt', { session: false }, (err: any, user: any, info: any) => {
      if (err) {
        return next(new CustomError('Authentication error', 500));
      }

      if (!user) {
        return next(new CustomError('Authentication required', 401));
      }

      req.user = user;
      next();
    })(req, res, next);
  } catch (error) {
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
