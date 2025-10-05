import { Response } from 'express';
import { ApiResponse } from '../types';

export class ResponseHelper {
  static success(res: Response, data?: any, message?: string, statusCode: number = 200): void {
    const response: ApiResponse = {
      success: true,
      data,
      message
    };

    res.status(statusCode).json(response);
  }

  static error(res: Response, message: string, statusCode: number = 400, details?: any): void {
    const response: ApiResponse = {
      success: false,
      error: {
        message,
        statusCode,
        details
      }
    };

    res.status(statusCode).json(response);
  }

  static created(res: Response, data?: any, message?: string): void {
    this.success(res, data, message, 201);
  }

  static notFound(res: Response, message: string = 'Resource not found'): void {
    this.error(res, message, 404);
  }

  static unauthorized(res: Response, message: string = 'Unauthorized'): void {
    this.error(res, message, 401);
  }

  static forbidden(res: Response, message: string = 'Forbidden'): void {
    this.error(res, message, 403);
  }

  static badRequest(res: Response, message: string = 'Bad request', details?: any): void {
    this.error(res, message, 400, details);
  }

  static internalError(res: Response, message: string = 'Internal server error'): void {
    this.error(res, message, 500);
  }
}
