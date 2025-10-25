import jwt from 'jsonwebtoken';
import { config } from '../../config/env.config';
import { UserPayload } from '../../types';
import { CustomError } from '../../middlewares/error.middleware';
import { Service } from '../../decorators/service.decorator';

export interface TokenPayload {
  userId: string;
  email: string;
  role: string;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
}

@Service()
export class AuthService {
  generateAccessToken(payload: TokenPayload): string {
    return jwt.sign(payload, config.jwt.secret, {
      expiresIn: config.jwt.expiresIn,
      issuer: 'cyberix-server',
      audience: 'cyberix-client'
    } as jwt.SignOptions);
  }

  generateRefreshToken(payload: TokenPayload): string {
    return jwt.sign(payload, config.jwt.refreshSecret, {
      expiresIn: config.jwt.refreshExpiresIn,
      issuer: 'cyberix-server',
      audience: 'cyberix-client'
    } as jwt.SignOptions);
  }

  generateTokens(user: UserPayload): AuthTokens {
    const payload: TokenPayload = {
      userId: user.id,
      email: user.email,
      role: user.role
    };

    return {
      accessToken: this.generateAccessToken(payload),
      refreshToken: this.generateRefreshToken(payload)
    };
  }

  verifyAccessToken(token: string): TokenPayload {
    try {
      return jwt.verify(token, config.jwt.secret, {
        issuer: 'cyberix-server',
        audience: 'cyberix-client'
      }) as TokenPayload;
    } catch (error) {
      throw new CustomError('Invalid or expired token', 401);
    }
  }

  verifyRefreshToken(token: string): TokenPayload {
    try {
      return jwt.verify(token, config.jwt.refreshSecret, {
        issuer: 'cyberix-server',
        audience: 'cyberix-client'
      }) as TokenPayload;
    } catch (error) {
      throw new CustomError('Invalid or expired refresh token', 401);
    }
  }

  async refreshTokens(refreshToken: string): Promise<AuthTokens> {
    const payload = this.verifyRefreshToken(refreshToken);
    
    // In a real application, you would verify the refresh token exists in the database
    // and is not expired/revoked
    
    return this.generateTokens({
      id: payload.userId,
      email: payload.email,
      username: '', // This would be fetched from database
      role: payload.role,
      isActive: true
    });
  }

  extractTokenFromHeader(authHeader: string | undefined): string {
    if (!authHeader) {
      throw new CustomError('Authorization header is required', 401);
    }

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      throw new CustomError('Invalid authorization header format', 401);
    }

    const token = parts[1];
    if (!token) {
      throw new CustomError('Token is missing from authorization header', 401);
    }

    return token;
  }
}
