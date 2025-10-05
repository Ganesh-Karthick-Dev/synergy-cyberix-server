import { Request, Response, NextFunction } from 'express';
import passport from 'passport';
import { CustomError } from './error.middleware';

// Extend Request interface to include user
declare global {
  namespace Express {
    interface User {
      id: string;
      email: string;
      username: string;
      role: string;
      isActive: boolean;
    }
  }
}

export const authenticate = (req: Request, res: Response, next: NextFunction): void => {
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

export const optionalAuth = (req: Request, res: Response, next: NextFunction): void => {
  passport.authenticate('jwt', { session: false }, (err: any, user: any) => {
    if (err) {
      return next(new CustomError('Authentication error', 500));
    }

    req.user = user || null;
    next();
  })(req, res, next);
};
