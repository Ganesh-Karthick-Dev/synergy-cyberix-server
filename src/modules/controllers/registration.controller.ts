import { Request, Response } from 'express';
import { Controller, Post } from '../../decorators/controller.decorator';
import { Validate, RegisterUserValidation } from '../../decorators/validation.decorator';
import { Service, Inject } from '../../decorators/service.decorator';
import { RegisterUserDto } from '../dtos/user.dto';
import { ApiResponse } from '../../types';
import { UserService } from '../services/user.service';

@Service()
@Controller('/api')
export class RegistrationController {
  private userService: UserService;

  constructor() {
    this.userService = new UserService();
  }

  @Post('/register')
  @Validate(RegisterUserValidation)
  async registerUser(req: Request, res: Response): Promise<void> {
    try {
      const registerData: RegisterUserDto = req.body;

      console.log(`registerData: ${JSON.stringify(registerData)}`);
      
      const result = await this.userService.registerUser(registerData);

      const response: ApiResponse = {
        success: true,
        data: result,
        message: 'User registered successfully. Please check your email for login credentials.'
      };

      res.status(201).json(response);
    } catch (error) {
      // Handle different types of errors
      let statusCode = 400;
      let message = 'Registration failed';

      if (error instanceof Error) {
        if (error.message.includes('already exists')) {
          statusCode = 409; // Conflict
          message = error.message;
        } else if (error.message.includes('Service plan not found')) {
          statusCode = 400;
          message = error.message;
        } else if (error.message.includes('Registration failed')) {
          statusCode = 500;
          message = 'Database transaction failed. Please try again.';
        } else {
          message = error.message;
        }
      }

      res.status(statusCode).json({
        success: false,
        error: {
          message,
          statusCode
        }
      });
    }
  }

  @Post('/')
  async getApiInfo(req: Request, res: Response): Promise<void> {
    res.json({
      success: true,
      message: 'Cyberix Security API Server',
      version: '1.0.0',
      endpoints: {
        register: 'POST /api/register',
        health: 'GET /health'
      },
      description: 'Cybersecurity platform with user registration and management'
    });
  }
}
