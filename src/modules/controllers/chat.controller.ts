import { Request, Response } from 'express';
import { Controller, Post } from '../../decorators/controller.decorator';
import { Validate } from '../../decorators/validation.decorator';
import { Service } from '../../decorators/service.decorator';
import { ApiResponse } from '../../types';
import { body } from 'express-validator';
import { ChatService } from '../services/chat.service';

@Service()
@Controller('/api/chat')
export class ChatController {
  private chatService: ChatService;

  constructor() {
    this.chatService = new ChatService();
  }

  @Post('/')
  @Validate([
    body('message').notEmpty().withMessage('Message is required'),
    body('conversationHistory').optional().isArray().withMessage('Conversation history must be an array'),
  ])
  async sendMessage(req: Request, res: Response): Promise<void> {
    try {
      const { message, conversationHistory = [] } = req.body;

      if (!message || typeof message !== 'string') {
        res.status(400).json({
          success: false,
          error: {
            message: 'Message is required and must be a string',
            statusCode: 400
          }
        });
        return;
      }

      // Validate conversation history structure
      if (conversationHistory && Array.isArray(conversationHistory)) {
        for (const msg of conversationHistory) {
          if (!msg.sender || !msg.text) {
            res.status(400).json({
              success: false,
              error: {
                message: 'Invalid conversation history format. Each message must have sender and text fields.',
                statusCode: 400
              }
            });
            return;
          }
        }
      }

      // Call chat service
      try {
        const aiResponse = await this.chatService.sendMessage(message, conversationHistory);

        const response: ApiResponse = {
          success: true,
          data: {
            response: aiResponse
          },
          message: 'Message processed successfully'
        };

        res.status(200).json(response);
      } catch (serviceError: any) {
        // Log the full error for debugging
        console.error('[ChatController] Full error details:', {
          message: serviceError.message,
          statusCode: serviceError.statusCode,
          stack: serviceError.stack
        });
        throw serviceError; // Re-throw to be caught by outer catch
      }
    } catch (error: any) {
      console.error('[ChatController] Error:', error);
      
      const statusCode = error.statusCode || 500;
      const errorMessage = error.message || 'Failed to process chat message';

      res.status(statusCode).json({
        success: false,
        error: {
          message: errorMessage,
          statusCode: statusCode
        }
      });
    }
  }
}

