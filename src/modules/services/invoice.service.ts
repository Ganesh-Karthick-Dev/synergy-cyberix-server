import PDFDocument from 'pdfkit';
import { Service } from '../../decorators/service.decorator';
import { prisma } from '../../config/db';
import { CustomError } from '../../middlewares/error.middleware';
import { logger } from '../../utils/logger';
import fs from 'fs';
import path from 'path';

export interface InvoiceData {
  invoiceNumber: string;
  paymentId: string;
  orderId: string;
  userId: string;
  userName: string;
  userEmail: string;
  planName: string;
  planDescription: string;
  amount: number;
  currency: string;
  paymentDate: Date;
  paymentMethod: string;
  transactionId: string;
}

@Service()
export class InvoiceService {
  private readonly INVOICE_DIR = path.join(process.cwd(), 'invoices');

  constructor() {
    // Ensure invoices directory exists
    if (!fs.existsSync(this.INVOICE_DIR)) {
      fs.mkdirSync(this.INVOICE_DIR, { recursive: true });
    }
  }

  async generateInvoice(paymentId: string): Promise<Buffer> {
    try {
      console.log('[Invoice Service] ===== GENERATING INVOICE =====');
      console.log('[Invoice Service] Payment ID:', paymentId);

      // Fetch payment data with related information
      const payment = await prisma.payment.findUnique({
        where: { id: paymentId },
        include: {
          order: {
            include: {
              plan: true,
              user: {
                select: {
                  id: true,
                  email: true,
                  firstName: true,
                  lastName: true
                }
              }
            }
          }
        }
      });

      if (!payment) {
        throw new CustomError('Payment not found', 404);
      }

      if (!payment.order) {
        throw new CustomError('Payment order not found', 404);
      }

      console.log('[Invoice Service] Payment data retrieved successfully');

      // Prepare invoice data
      const invoiceData: InvoiceData = {
        invoiceNumber: `INV-${payment.id.slice(-8).toUpperCase()}`,
        paymentId: payment.id,
        orderId: payment.orderId,
        userId: payment.order.userId,
        userName: `${payment.order.user.firstName || ''} ${payment.order.user.lastName || ''}`.trim() || 'Customer',
        userEmail: payment.order.user.email,
        planName: payment.order.plan?.name || 'Plan',
        planDescription: payment.order.plan?.description || 'Cybersecurity Service Plan',
        amount: parseFloat(payment.amount.toString()),
        currency: payment.currency,
        paymentDate: payment.paidAt || payment.createdAt,
        paymentMethod: payment.method || 'Razorpay',
        transactionId: payment.razorpayPaymentId
      };

      console.log('[Invoice Service] Invoice data prepared:', {
        invoiceNumber: invoiceData.invoiceNumber,
        amount: invoiceData.amount,
        userEmail: invoiceData.userEmail
      });

      // Generate PDF
      const pdfBuffer = await this.createPDF(invoiceData);

      console.log('[Invoice Service] ✅ Invoice PDF generated successfully');
      return pdfBuffer;

    } catch (error) {
      console.error('[Invoice Service] ❌ Invoice generation failed:', error);
      logger.error('Error generating invoice:', error);
      throw new CustomError('Failed to generate invoice', 500);
    }
  }

  private async createPDF(invoiceData: InvoiceData): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      try {
        const doc = new PDFDocument({
          size: 'A4',
          margin: 50
        });

        const buffers: Buffer[] = [];

        doc.on('data', buffers.push.bind(buffers));
        doc.on('end', () => {
          const pdfBuffer = Buffer.concat(buffers);
          resolve(pdfBuffer);
        });

        doc.on('error', reject);

        // Header Section with Orange Accent
        doc.fillColor('#ff7b00').rect(0, 0, 595, 100).fill();
        doc.fillColor('#ffffff');
        doc.fontSize(28).font('Helvetica-Bold').text('INVOICE', 50, 35, { align: 'left' });
        doc.fillColor('#000000');

        // Top Section: Company Info (Left) and Invoice Details (Right)
        const startY = 120;
        let currentY = startY;

        // Company Info (Left Side)
        doc.fillColor('#000000');
        doc.fontSize(18).font('Helvetica-Bold').text('Cyberix Security', 50, currentY);
        currentY += 25;
        doc.fontSize(10).font('Helvetica');
        doc.text('123 Security Street', 50, currentY);
        currentY += 15;
        doc.text('Cyber City, CC 12345', 50, currentY);
        currentY += 15;
        doc.text('Email: support@cyberix.com', 50, currentY);
        currentY += 15;
        doc.text('Phone: +1 (555) 123-4567', 50, currentY);

        // Invoice Details Box (Right Side)
        const invoiceBoxX = 350;
        const invoiceBoxY = startY;
        const invoiceBoxWidth = 195;
        const invoiceBoxHeight = 90;

        // Draw box background
        doc.fillColor('#f5f5f5').rect(invoiceBoxX, invoiceBoxY, invoiceBoxWidth, invoiceBoxHeight).fill();
        doc.strokeColor('#cccccc').rect(invoiceBoxX, invoiceBoxY, invoiceBoxWidth, invoiceBoxHeight).stroke();
        
        doc.fillColor('#000000');
        doc.fontSize(10).font('Helvetica-Bold').text('Invoice Details', invoiceBoxX + 10, invoiceBoxY + 10);
        doc.fontSize(9).font('Helvetica');
        doc.text(`Invoice #: ${invoiceData.invoiceNumber}`, invoiceBoxX + 10, invoiceBoxY + 25);
        const invoiceDateTime = invoiceData.paymentDate.toLocaleString('en-US', {
          year: 'numeric',
          month: '2-digit',
          day: '2-digit',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
          hour12: true
        });
        doc.text(`Date & Time: ${invoiceDateTime}`, invoiceBoxX + 10, invoiceBoxY + 40);
        doc.text(`Payment ID:`, invoiceBoxX + 10, invoiceBoxY + 55);
        doc.fontSize(8).text(invoiceData.transactionId, invoiceBoxX + 10, invoiceBoxY + 70, { width: 175 });

        // Bill To Section
        currentY = startY + 120;
        doc.fillColor('#ff7b00');
        doc.fontSize(12).font('Helvetica-Bold').text('Bill To:', 50, currentY);
        currentY += 20;
        doc.fillColor('#000000');
        doc.fontSize(11).font('Helvetica-Bold').text(invoiceData.userName, 50, currentY);
        currentY += 15;
        doc.fontSize(10).font('Helvetica').text(invoiceData.userEmail, 50, currentY);

        // Service Details Table
        currentY += 40;
        doc.fillColor('#ff7b00');
        doc.fontSize(12).font('Helvetica-Bold').text('Service Details', 50, currentY);
        currentY += 20;

        // Table Header Background
        doc.rect(50, currentY, 495, 25).fill('#ff7b00');
        doc.fillColor('#ffffff');
        doc.fontSize(10).font('Helvetica-Bold');
        doc.text('Description', 60, currentY + 8);
        doc.text('Qty', 350, currentY + 8);
        doc.text('Unit Price', 400, currentY + 8);
        doc.text('Amount', 480, currentY + 8);

        // Table Row
        currentY += 25;
        doc.fillColor('#ffffff').rect(50, currentY, 495, 30).fill();
        doc.strokeColor('#e0e0e0').rect(50, currentY, 495, 30).stroke();
        doc.fillColor('#000000');
        
        // Wrap description text
        const descriptionY = currentY + 8;
        doc.fontSize(9).font('Helvetica');
        doc.text(invoiceData.planDescription, 60, descriptionY, { width: 280, ellipsis: true });
        doc.text('1', 350, descriptionY + 8);
        doc.text(`${invoiceData.currency} ${invoiceData.amount.toFixed(2)}`, 400, descriptionY + 8);
        doc.font('Helvetica-Bold').text(`${invoiceData.currency} ${invoiceData.amount.toFixed(2)}`, 480, descriptionY + 8);

        // Total Section
        currentY += 50;
        const totalBoxY = currentY;
        doc.fillColor('#f5f5f5').rect(350, totalBoxY, 195, 50).fill();
        doc.strokeColor('#cccccc').rect(350, totalBoxY, 195, 50).stroke();
        doc.fillColor('#000000');
        doc.fontSize(11).font('Helvetica-Bold').text('Total Amount', 360, totalBoxY + 10);
        doc.fontSize(16).font('Helvetica-Bold').fillColor('#ff7b00');
        doc.text(`${invoiceData.currency} ${invoiceData.amount.toFixed(2)}`, 360, totalBoxY + 28);

        // Footer
        const footerY = currentY + 100;
        doc.strokeColor('#cccccc').moveTo(50, footerY).lineTo(545, footerY).stroke();
        doc.fillColor('#666666');
        doc.fontSize(9).font('Helvetica').text('Thank you for choosing Cyberix Security!', 50, footerY + 10, { align: 'center' });
        doc.text('For support, contact us at support@cyberix.com', 50, footerY + 25, { align: 'center' });

        doc.end();

      } catch (error) {
        reject(error);
      }
    });
  }

  async getInvoice(paymentId: string): Promise<{ buffer: Buffer; filename: string }> {
    const buffer = await this.generateInvoice(paymentId);
    const filename = `invoice-${paymentId.slice(-8)}.pdf`;

    return { buffer, filename };
  }
}
