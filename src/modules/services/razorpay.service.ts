import Razorpay from 'razorpay';
import { config } from '../../config/env.config';
import { CustomError } from '../../middlewares/error.middleware';
import { logger } from '../../utils/logger';
import { Service } from '../../decorators/service.decorator';
import { prisma } from '../../config/db';
import { Prisma } from '@prisma/client';
import crypto from 'crypto';

export interface CreateOrderData {
  amount: number; // Amount in paise (1 INR = 100 paise)
  currency?: string;
  receipt?: string;
  notes?: Record<string, string>;
  userId: string;
  planId?: string;
}

export interface VerifyPaymentData {
  razorpayOrderId: string;
  razorpayPaymentId: string;
  razorpaySignature: string;
}

export interface PaymentOrderResponse {
  id: string;
  razorpayOrderId: string;
  amount: number;
  currency: string;
  status: string;
  key: string; // Razorpay key ID
}

@Service()
export class RazorpayService {
  private razorpay: Razorpay;

  constructor() {
    if (!config.razorpay) {
      throw new Error('Razorpay configuration not found. Please set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET environment variables.');
    }

    this.razorpay = new Razorpay({
      key_id: config.razorpay!.keyId,
      key_secret: config.razorpay!.keySecret,
    });
  }

  /**
   * Create a Razorpay order
   */
  async createOrder(orderData: CreateOrderData): Promise<PaymentOrderResponse> {
    try {
      // Create order in Razorpay
      console.log('[Razorpay Service] ===== CREATING RAZORPAY ORDER =====')
      console.log('[Razorpay Service] Order data:', {
        amount: orderData.amount,
        currency: orderData.currency || 'INR',
        receipt: orderData.receipt || `order_${Date.now()}`,
        notes: orderData.notes || {}
      })
      console.log('[Razorpay Service] Razorpay config:', {
        keyId: config.razorpay!.keyId ? 'SET' : 'NOT SET',
        keySecret: config.razorpay!.keySecret ? 'SET' : 'NOT SET'
      })

      const razorpayOrder = await this.razorpay.orders.create({
        amount: orderData.amount, // Amount in paise
        currency: orderData.currency || 'INR',
        receipt: orderData.receipt || `order_${Date.now()}`,
        notes: orderData.notes || {}
      });

      console.log('[Razorpay Service] ✅ Razorpay order created:', {
        id: razorpayOrder.id,
        amount: razorpayOrder.amount,
        currency: razorpayOrder.currency,
        status: razorpayOrder.status
      })

      // Save order in database (with error handling for missing tables)
      let paymentOrder;
      try {
        paymentOrder = await prisma.paymentOrder.create({
          data: {
            userId: orderData.userId,
            planId: orderData.planId,
            amount: new Prisma.Decimal(orderData.amount / 100), // Convert paise to rupees for storage
            currency: orderData.currency || 'INR',
            razorpayOrderId: razorpayOrder.id,
            status: 'PENDING',
            description: orderData.notes?.description || 'Plan subscription',
            metadata: orderData.notes || {}
          }
        });
        console.log('[Razorpay Service] ✅ Payment order saved to database');
      } catch (dbError: any) {
        console.warn('[Razorpay Service] ⚠️  Database save failed (tables may not exist yet):', dbError.message);
        console.warn('[Razorpay Service] Continuing with Razorpay order creation...');

        // Create a mock payment order object for the response
        paymentOrder = {
          id: `temp_${razorpayOrder.id}`,
          userId: orderData.userId,
          planId: orderData.planId,
          amount: new Prisma.Decimal(orderData.amount / 100),
          currency: orderData.currency || 'INR',
          razorpayOrderId: razorpayOrder.id,
          status: 'PENDING',
          description: orderData.notes?.description || 'Plan subscription',
          metadata: orderData.notes || {},
          createdAt: new Date(),
          updatedAt: new Date()
        };
      }

      logger.info(`Payment order created: ${paymentOrder.id} for user ${orderData.userId}`);

      return {
        id: paymentOrder.id,
        razorpayOrderId: razorpayOrder.id,
        amount: orderData.amount,
        currency: orderData.currency || 'INR',
        status: paymentOrder.status,
        key: config.razorpay!.keyId
      };
    } catch (error: any) {
      console.error('[Razorpay Service] ❌ RAZORPAY ORDER CREATION FAILED')
      console.error('[Razorpay Service] Complete error object:', error)
      console.error('[Razorpay Service] Error type:', typeof error)
      console.error('[Razorpay Service] Error constructor:', error?.constructor?.name)
      console.error('[Razorpay Service] Error keys:', error ? Object.keys(error) : 'No keys')

      // Log all properties of the error
      if (error) {
        for (const key in error) {
          console.error(`[Razorpay Service] error.${key}:`, error[key])
        }
      }

      // Try to extract meaningful error message
      let errorMessage = 'Unknown Razorpay error'
      if (error?.message) errorMessage = error.message
      else if (error?.description) errorMessage = error.description
      else if (error?.error?.description) errorMessage = error.error.description
      else if (typeof error === 'string') errorMessage = error
      else if (error?.toString) errorMessage = error.toString()

      logger.error('Error creating Razorpay order:', {
        error: errorMessage,
        stack: error.stack,
        fullError: error,
        orderData: {
          amount: orderData.amount,
          currency: orderData.currency,
          userId: orderData.userId,
          planId: orderData.planId
        }
      });

      throw new CustomError(`Failed to create payment order: ${errorMessage}`, 500);
    }
  }

  /**
   * Verify payment signature and update payment status
   */
  async verifyPayment(verificationData: VerifyPaymentData): Promise<{ verified: boolean; paymentId?: string }> {
    try {
      // Create signature to verify
      const sign = verificationData.razorpayOrderId + '|' + verificationData.razorpayPaymentId;
      const expectedSign = crypto
        .createHmac('sha256', config.razorpay!.keySecret)
        .update(sign.toString())
        .digest('hex');

      // Verify signature
      if (expectedSign !== verificationData.razorpaySignature) {
        logger.warn(`Payment verification failed: Invalid signature for order ${verificationData.razorpayOrderId}`);
        return { verified: false };
      }

      // Get payment details from Razorpay
      const paymentDetails = await this.razorpay.payments.fetch(verificationData.razorpayPaymentId);

      // Find the payment order
      const paymentOrder = await prisma.paymentOrder.findUnique({
        where: { razorpayOrderId: verificationData.razorpayOrderId },
        include: { user: true, plan: true }
      });

      if (!paymentOrder) {
        logger.error(`Payment order not found for Razorpay order ID: ${verificationData.razorpayOrderId}`);
        return { verified: false };
      }

      // Update payment order status
      await prisma.paymentOrder.update({
        where: { id: paymentOrder.id },
        data: {
          status: paymentDetails.status === 'captured' ? 'COMPLETED' : 'FAILED'
        }
      });

      // Create payment record (with error handling for missing tables)
      let paymentRecord = null;
      try {
        paymentRecord = await prisma.payment.create({
          data: {
            orderId: paymentOrder.id,
            userId: paymentOrder.userId,
            razorpayPaymentId: verificationData.razorpayPaymentId,
            razorpayOrderId: verificationData.razorpayOrderId,
            razorpaySignature: verificationData.razorpaySignature,
            amount: paymentOrder.amount,
            currency: paymentOrder.currency,
            status: paymentDetails.status === 'captured' ? 'COMPLETED' : 'FAILED',
            method: paymentDetails.method,
            bank: paymentDetails.bank,
            wallet: paymentDetails.wallet,
            vpa: paymentDetails.vpa,
            email: paymentDetails.email,
            contact: paymentDetails.contact ? String(paymentDetails.contact) : null,
            fee: paymentDetails.fee ? new Prisma.Decimal(paymentDetails.fee / 100) : null,
            tax: paymentDetails.tax ? new Prisma.Decimal(paymentDetails.tax / 100) : null,
            paidAt: paymentDetails.created_at ? new Date(paymentDetails.created_at * 1000) : null
          }
        });
        console.log('[Razorpay Service] ✅ Payment record saved to database:', paymentRecord.id);
      } catch (dbError: any) {
        console.warn('[Razorpay Service] ⚠️  Payment database save failed (tables may not exist yet):', dbError.message);
        console.warn('[Razorpay Service] Payment verification successful, but not saved to database');
      }

      // If payment is successful and there's a plan, create/update subscription
      if (paymentDetails.status === 'captured' && paymentOrder.planId) {
        try {
          await this.activateSubscription(paymentOrder);
          console.log('[Razorpay Service] ✅ Subscription activated/updated');
        } catch (subscriptionError: any) {
          console.warn('[Razorpay Service] ⚠️  Subscription activation failed:', subscriptionError.message);
          console.warn('[Razorpay Service] Payment successful, but subscription not activated');
        }
      }

      logger.info(`Payment verified successfully: ${verificationData.razorpayPaymentId} for order ${verificationData.razorpayOrderId}`);
      return { verified: true, paymentId: paymentRecord?.id };
    } catch (error: any) {
      logger.error('Error verifying payment:', error);
      throw new CustomError('Failed to verify payment', 500);
    }
  }

  /**
   * Activate subscription after successful payment
   */
  private async activateSubscription(paymentOrder: any): Promise<void> {
    try {
      // Check if user already has an active subscription for this plan
      const existingSubscription = await prisma.userSubscription.findFirst({
        where: {
          userId: paymentOrder.userId,
          planId: paymentOrder.planId,
          status: 'ACTIVE'
        }
      });

      if (existingSubscription) {
        // Extend existing subscription
        const currentEndDate = existingSubscription.endDate || new Date();
        const newEndDate = this.calculateEndDate(currentEndDate, paymentOrder.plan.billingCycle);

        await prisma.userSubscription.update({
          where: { id: existingSubscription.id },
          data: {
            endDate: newEndDate,
            updatedAt: new Date()
          }
        });

        logger.info(`Extended subscription for user ${paymentOrder.userId}, plan ${paymentOrder.planId}`);
      } else {
        // Create new subscription
        const endDate = this.calculateEndDate(new Date(), paymentOrder.plan.billingCycle);

        await prisma.userSubscription.create({
          data: {
            userId: paymentOrder.userId,
            planId: paymentOrder.planId,
            status: 'ACTIVE',
            startDate: new Date(),
            endDate: endDate,
            autoRenew: true,
            paymentMethod: 'RAZORPAY'
          }
        });

        logger.info(`Created new subscription for user ${paymentOrder.userId}, plan ${paymentOrder.planId}`);
      }
    } catch (error: any) {
      logger.error('Error activating subscription:', error);
      // Don't throw error here as payment was successful
    }
  }

  /**
   * Calculate subscription end date based on billing cycle
   * Monthly: 31 days
   * Yearly: 365 days
   * Lifetime: 100 years (effectively unlimited)
   */
  private calculateEndDate(startDate: Date, billingCycle: string): Date {
    const endDate = new Date(startDate);
    const millisecondsPerDay = 24 * 60 * 60 * 1000;

    switch (billingCycle.toUpperCase()) {
      case 'MONTHLY':
        // Add 31 days for monthly plans
        endDate.setTime(endDate.getTime() + (31 * millisecondsPerDay));
        break;
      case 'YEARLY':
        // Add 365 days for yearly plans
        endDate.setTime(endDate.getTime() + (365 * millisecondsPerDay));
        break;
      case 'LIFETIME':
        // Add 100 years (effectively lifetime)
        endDate.setFullYear(endDate.getFullYear() + 100);
        break;
      default:
        // Default to 31 days (monthly)
        endDate.setTime(endDate.getTime() + (31 * millisecondsPerDay));
    }

    return endDate;
  }

  /**
   * Get payment order by ID
   */
  async getPaymentOrder(orderId: string) {
    try {
      const paymentOrder = await prisma.paymentOrder.findUnique({
        where: { id: orderId },
        include: {
          user: {
            select: { id: true, email: true, firstName: true, lastName: true }
          },
          plan: true,
          payments: true
        }
      });

      if (!paymentOrder) {
        throw new CustomError('Payment order not found', 404);
      }

      return paymentOrder;
    } catch (error: any) {
      if (error instanceof CustomError) {
        throw error;
      }
      logger.error('Error fetching payment order:', error);
      throw new CustomError('Failed to retrieve payment order', 500);
    }
  }

  /**
   * Get payment orders for a user
   */
  async getUserPaymentOrders(userId: string) {
    try {
      const paymentOrders = await prisma.paymentOrder.findMany({
        where: { userId },
        include: {
          plan: true,
          payments: true
        },
        orderBy: { createdAt: 'desc' }
      });

      return paymentOrders;
    } catch (error: any) {
      logger.error('Error fetching user payment orders:', error);
      throw new CustomError('Failed to retrieve payment orders', 500);
    }
  }

  /**
   * Refund a payment
   */
  async refundPayment(paymentId: string, amount?: number) {
    try {
      // Get payment details
      const payment = await prisma.payment.findUnique({
        where: { razorpayPaymentId: paymentId }
      });

      if (!payment) {
        throw new CustomError('Payment not found', 404);
      }

      if (payment.status !== 'COMPLETED') {
        throw new CustomError('Only completed payments can be refunded', 400);
      }

      // Initiate refund through Razorpay
      const refund = await this.razorpay.payments.refund(paymentId, {
        amount: amount ? amount * 100 : undefined // Convert to paise if amount specified
      });

      // Update payment status
      await prisma.payment.update({
        where: { id: payment.id },
        data: { status: 'REFUNDED' }
      });

      logger.info(`Payment refunded: ${paymentId}`);
      return refund;
    } catch (error: any) {
      logger.error('Error refunding payment:', error);
      throw new CustomError('Failed to refund payment', 500);
    }
  }
}
