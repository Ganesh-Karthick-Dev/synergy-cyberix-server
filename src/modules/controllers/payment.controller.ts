import { Request, Response } from 'express';
import { Controller, Post, Get } from '../../decorators/controller.decorator';
import { Use } from '../../decorators/middleware.decorator';
import { Validate } from '../../decorators/validation.decorator';
import { Service } from '../../decorators/service.decorator';
import { ApiResponse } from '../../types';
import { body } from 'express-validator';
import { RazorpayService } from '../services/razorpay.service';
import { InvoiceService } from '../services/invoice.service';
import { authenticate } from '../../middlewares/auth.middleware';
import { prisma } from '../../config/db';

@Service()
@Controller('/api/payments')
export class PaymentController {
  private razorpayService: RazorpayService;
  private invoiceService: InvoiceService;

  constructor() {
    this.razorpayService = new RazorpayService();
    this.invoiceService = new InvoiceService();
  }

  /**
   * Create a payment order
   */
  @Post('/create-order')
  @Validate([
    body('amount').isNumeric().withMessage('Amount must be a number'),
    body('planId').optional().isString().withMessage('Plan ID must be a string'),
    body('currency').optional().isString().withMessage('Currency must be a string'),
    body('description').optional().isString().withMessage('Description must be a string')
  ])
  async createOrder(req: Request, res: Response): Promise<void> {
    try {
      const { amount, currency = 'INR', planId, description } = req.body;
      const userId = req.user?.id;

      if (!userId) {
        res.status(401).json({
          success: false,
          error: {
            message: 'User not authenticated',
            statusCode: 401
          }
        });
        return;
      }

      // Convert amount to paise (Razorpay expects amount in smallest currency unit)
      const amountInPaise = Math.round(amount * 100);

      const orderData = {
        amount: amountInPaise,
        currency,
        userId,
        planId,
        notes: {
          description: description || 'Plan subscription',
          userId,
          planId
        }
      };

      const order = await this.razorpayService.createOrder(orderData);

      const response: ApiResponse = {
        success: true,
        data: order,
        message: 'Payment order created successfully'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to create payment order',
          statusCode
        }
      });
    }
  }

  /**
   * Verify payment
   */
  @Post('/verify')
  @Validate([
    body('razorpayOrderId').notEmpty().withMessage('Razorpay order ID is required'),
    body('razorpayPaymentId').notEmpty().withMessage('Razorpay payment ID is required'),
    body('razorpaySignature').notEmpty().withMessage('Razorpay signature is required')
  ])
  async verifyPayment(req: Request, res: Response): Promise<void> {
    try {
      const { razorpayOrderId, razorpayPaymentId, razorpaySignature } = req.body;

      const verificationResult = await this.razorpayService.verifyPayment({
        razorpayOrderId,
        razorpayPaymentId,
        razorpaySignature
      });

      if (!verificationResult.verified) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Payment verification failed',
            statusCode: 400
          }
        });
        return;
      }

      const response: ApiResponse = {
        success: true,
        data: {
          verified: true,
          paymentId: verificationResult.paymentId
        },
        message: 'Payment verified successfully'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to verify payment',
          statusCode
        }
      });
    }
  }

  /**
   * Get payment order by ID
   */
  @Get('/orders/:orderId')
  async getPaymentOrder(req: Request, res: Response): Promise<void> {
    try {
      const { orderId } = req.params;
      const userId = req.user?.id;

      if (!orderId) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Order ID is required',
            statusCode: 400
          }
        });
        return;
      }

      if (!userId) {
        res.status(401).json({
          success: false,
          error: {
            message: 'User not authenticated',
            statusCode: 401
          }
        });
        return;
      }

      const order = await this.razorpayService.getPaymentOrder(orderId);

      // Check if user owns this order
      if (order.userId !== userId!) {
        res.status(403).json({
          success: false,
          error: {
            message: 'Access denied',
            statusCode: 403
          }
        });
        return;
      }

      const response: ApiResponse = {
        success: true,
        data: order,
        message: 'Payment order retrieved successfully'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to retrieve payment order',
          statusCode
        }
      });
    }
  }

  /**
   * Get user's payment orders
   */
  @Get('/orders')
  async getUserPaymentOrders(req: Request, res: Response): Promise<void> {
    try {
      const userId = req.user?.id;

      if (!userId) {
        res.status(401).json({
          success: false,
          error: {
            message: 'User not authenticated',
            statusCode: 401
          }
        });
        return;
      }

      const orders = await this.razorpayService.getUserPaymentOrders(userId);

      const response: ApiResponse = {
        success: true,
        data: orders,
        message: 'Payment orders retrieved successfully'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to retrieve payment orders',
          statusCode
        }
      });
    }
  }

  /**
   * Refund a payment (admin only)
   */
  @Post('/refund/:paymentId')
  @Validate([
    body('amount').optional().isNumeric().withMessage('Amount must be a number')
  ])
  async refundPayment(req: Request, res: Response): Promise<void> {
    try {
      const { paymentId } = req.params;
      const { amount } = req.body;
      const userRole = req.user?.role;

      if (!paymentId) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Payment ID is required',
            statusCode: 400
          }
        });
        return;
      }

      // Only admins can process refunds
      if (userRole !== 'ADMIN') {
        res.status(403).json({
          success: false,
          error: {
            message: 'Only administrators can process refunds',
            statusCode: 403
          }
        });
        return;
      }

      const refund = await this.razorpayService.refundPayment(paymentId, amount);

      const response: ApiResponse = {
        success: true,
        data: refund,
        message: 'Payment refunded successfully'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to refund payment',
          statusCode
        }
      });
    }
  }

  @Get('/invoice/:paymentId')
  @Use(authenticate)
  async downloadInvoice(req: Request, res: Response): Promise<void> {
    try {
      const { paymentId } = req.params;
      const userId = req.user?.id;

      if (!paymentId) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Payment ID is required',
            statusCode: 400
          }
        });
        return;
      }

      if (!userId) {
        res.status(401).json({
          success: false,
          error: {
            message: 'User not authenticated',
            statusCode: 401
          }
        });
        return;
      }

      // Verify that the payment belongs to the authenticated user
      const payment = await prisma.payment.findUnique({
        where: { id: paymentId },
        select: { userId: true }
      });

      if (!payment) {
        res.status(404).json({
          success: false,
          error: {
            message: 'Payment not found',
            statusCode: 404
          }
        });
        return;
      }

      if (payment.userId !== userId) {
        res.status(403).json({
          success: false,
          error: {
            message: 'Access denied',
            statusCode: 403
          }
        });
        return;
      }

      // Generate invoice
      const { buffer, filename } = await this.invoiceService.getInvoice(paymentId);

      // Set response headers for PDF download
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Content-Length', buffer.length);

      // Send the PDF buffer
      res.send(buffer);

    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to generate invoice',
          statusCode
        }
      });
    }
  }
}
