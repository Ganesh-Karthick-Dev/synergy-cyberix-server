import { Request, Response } from 'express';
import { Controller, Post } from '../../decorators/controller.decorator';
import { Validate } from '../../decorators/validation.decorator';
import { Service } from '../../decorators/service.decorator';
import { ApiResponse } from '../../types';
import { body } from 'express-validator';
import { EmailService } from '../services/email.service';

@Service()
@Controller('/api/contact')
export class ContactController {
  private emailService: EmailService;

  constructor() {
    this.emailService = new EmailService();
  }

  @Post('/')
  @Validate([
    body('name').notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Valid email is required'),
    body('subject').notEmpty().withMessage('Subject is required'),
    body('message').notEmpty().withMessage('Message is required'),
  ])
  async submitContactForm(req: Request, res: Response): Promise<void> {
    try {
      const { name, email, subject, message } = req.body;

      // Send email to admin
      await this.emailService.sendContactFormEmail(name, email, subject, message);

      const response: ApiResponse = {
        success: true,
        message: 'Thank you for your message! We\'ll get back to you soon.'
      };

      res.status(200).json(response);
    } catch (error: any) {
      console.error('[ContactController] Error:', error);
      res.status(500).json({
        success: false,
        error: {
          message: error.message || 'Failed to send contact form message',
          statusCode: 500
        }
      });
    }
  }
}

