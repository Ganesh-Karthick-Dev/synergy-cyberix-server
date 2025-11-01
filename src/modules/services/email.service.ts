import nodemailer from 'nodemailer';
import { config } from '../../config/env.config';
import { Service } from '../../decorators/service.decorator';

@Service()
export class EmailService {
  private transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      host: config.email?.host || 'smtp.gmail.com',
      port: config.email?.port || 587,
      secure: false, // true for 465, false for other ports
      auth: {
        user: config.email?.user || 'your-email@gmail.com',
        pass: config.email?.pass || 'your-app-password'
      }
    });
  }

  async sendRegistrationEmail(email: string, firstName: string, username: string, password: string): Promise<void> {
    const mailOptions = {
      from: `"Cyberix Security" <${config.email?.user || 'noreply@cyberix.com'}>`,
      to: email,
      subject: 'Welcome to Cyberix Security Platform - Your Account Details',
      html: this.getRegistrationEmailTemplate(firstName, username, password)
    };

    try {
      await this.transporter.sendMail(mailOptions);
      console.log(`Registration email sent to ${email}`);
    } catch (error) {
      console.error('Error sending registration email:', error);
      throw new Error('Failed to send registration email');
    }
  }

  private getRegistrationEmailTemplate(firstName: string, username: string, password: string): string {
    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Welcome to Cyberix Security</title>
        <style>
            /* Reset for Gmail responsiveness */
            body, table, td, a {
                -webkit-text-size-adjust: 100%;
                -ms-text-size-adjust: 100%;
            }
            table, td {
                border-collapse: collapse !important;
            }
            img {
                border: 0;
                line-height: 100%;
                text-decoration: none;
                -ms-interpolation-mode: bicubic;
            }
  
            body {
                margin: 0 !important;
                padding: 0 !important;
                width: 100% !important;
                height: 100% !important;
                background-color: #f9f9f9;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                color: #333;
            }
  
            .container {
                max-width: 600px;
                margin: 20px auto;
                background-color: #ffffff;
                border-radius: 12px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.08);
                overflow: hidden;
            }
  
            .header {
                background-color: #f97316; /* Orange Accent */
                padding: 30px 20px;
                text-align: center;
                color: #fff;
            }
            .header .logo {
                font-size: 26px;
                font-weight: bold;
                margin-bottom: 6px;
            }
            .header .tagline {
                font-size: 14px;
                opacity: 0.9;
            }
  
            .content {
                padding: 30px 25px;
            }
  
            h2 {
                color: #f97316;
                margin-bottom: 12px;
            }
  
            .credentials {
                background-color: #fff8f3;
                border: 1px solid #fcd9bd;
                border-radius: 8px;
                padding: 20px;
                margin: 20px 0;
            }
            .credentials h3 {
                margin-top: 0;
                color: #f97316;
            }
            .credential-item {
                display: flex;
                justify-content: space-between;
                margin-bottom: 12px;
                border-bottom: 1px solid #f1f1f1;
                padding-bottom: 8px;
            }
            .credential-item:last-child {
                border-bottom: none;
                margin-bottom: 0;
                padding-bottom: 0;
            }
            .credential-label {
                font-weight: 600;
                color: #444;
            }
            .credential-value {
                font-family: monospace;
                background: #fff;
                padding: 4px 10px;
                border: 1px solid #e2e2e2;
                border-radius: 4px;
                color: #f97316;
                font-weight: bold;
            }
  
            .warning {
                background-color: #fff4e5;
                border-left: 4px solid #f97316;
                padding: 15px;
                border-radius: 6px;
                margin: 20px 0;
                color: #8a4b08;
                font-size: 14px;
            }
  
            .features {
                background-color: #f9fafb;
                padding: 20px;
                border-radius: 8px;
                margin: 20px 0;
            }
            .features h3 {
                margin-top: 0;
                color: #f97316;
            }
            .feature-list {
                list-style: none;
                padding: 0;
                margin: 0;
            }
            .feature-list li {
                padding: 6px 0;
                font-size: 14px;
                color: #333;
            }
            .feature-list li:before {
                content: "✔";
                margin-right: 8px;
                color: #f97316;
                font-weight: bold;
            }
  
            .button {
                display: inline-block;
                background-color: #f97316;
                color: #ffffff !important;
                text-decoration: none;
                padding: 14px 28px;
                border-radius: 6px;
                font-weight: bold;
                margin: 20px 0;
                text-align: center;
            }
  
            .footer {
                text-align: center;
                font-size: 12px;
                color: #999;
                border-top: 1px solid #eee;
                padding: 20px;
                background: #fafafa;
            }
  
            @media screen and (max-width: 600px) {
                .content {
                    padding: 20px 15px;
                }
                h2 {
                    font-size: 20px;
                }
                .button {
                    width: 100% !important;
                    display: block;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">🛡️ Cyberix Security</div>
                <div class="tagline">Advanced Cybersecurity Solutions</div>
            </div>
  
            <div class="content">
                <h2>Welcome, ${firstName}!</h2>
                <p>Thank you for registering with <strong>Cyberix Security</strong>. We’re thrilled to have you join our community of cybersecurity professionals.</p>
                <p>Your account has been created under the <strong>FREE</strong> plan. Upgrade anytime to unlock more advanced features.</p>
  
                <div class="credentials">
                    <h3>🔐 Your Login Credentials</h3>
                    <div class="credential-item">
                        <span class="credential-label">Password:</span>
                        <span class="credential-value">${password}</span>
                    </div>
                </div>
  
                <div class="warning">
                    ⚠️ <strong>Security Notice:</strong> Please change your password immediately after first login. Never share your credentials with anyone.
                </div>
  
                <p>If you need help, our support team is ready to assist anytime.</p>
            </div>
  
            <div class="footer">
                © 2024 Cyberix Security. All rights reserved.<br>
                This is an automated email, please do not reply.
            </div>
        </div>
    </body>
    </html>
    `;
  }
  

  async verifyConnection(): Promise<boolean> {
    try {
      await this.transporter.verify();
      return true;
    } catch (error) {
      console.error('Email service connection failed:', error);
      return false;
    }
  }

  /**
   * Send suspicious activity alert email
   */
  async sendSuspiciousActivityAlert(
    email: string, 
    activityDetails: {
      type: 'ACCOUNT_BLOCKED' | 'MULTIPLE_FAILED_ATTEMPTS' | 'UNAUTHORIZED_ADMIN_ACCESS';
      attempts: number;
      ipAddress?: string;
      userAgent?: string;
      blockedAt: Date;
      expiresAt: Date;
      remainingMinutes: number;
    }
  ): Promise<void> {
    const { type, attempts, ipAddress, userAgent, blockedAt, expiresAt, remainingMinutes } = activityDetails;
    
    let subject = '';
    let title = '';
    let description = '';
    let actionRequired = '';

    switch (type) {
      case 'ACCOUNT_BLOCKED':
        subject = '🚨 Account Security Alert - Multiple Failed Login Attempts';
        title = 'Account Temporarily Blocked';
        description = `Your account has been temporarily blocked due to ${attempts} consecutive failed login attempts.`;
        actionRequired = 'Please wait for the block to expire or contact support if you believe this is an error.';
        break;
      case 'MULTIPLE_FAILED_ATTEMPTS':
        subject = '⚠️ Suspicious Login Activity Detected';
        title = 'Multiple Failed Login Attempts';
        description = `We detected ${attempts} failed login attempts on your account.`;
        actionRequired = 'If this was not you, please change your password immediately and contact support.';
        break;
      case 'UNAUTHORIZED_ADMIN_ACCESS':
        subject = '🚨 Security Alert - Unauthorized Admin Access Attempt';
        title = 'Unauthorized Admin Access Attempt';
        description = 'Someone attempted to access admin features without proper authorization.';
        actionRequired = 'This attempt has been blocked and logged. No further action required.';
        break;
    }

    const mailOptions = {
      from: `"Cyberix Security" <${config.email?.user || 'noreply@cyberix.com'}>`,
      to: email,
      subject: subject,
      html: this.getSuspiciousActivityEmailTemplate(
        title, 
        description, 
        actionRequired, 
        email, 
        attempts, 
        blockedAt, 
        expiresAt, 
        remainingMinutes,
        ipAddress, 
        userAgent
      )
    };

    try {
      await this.transporter.sendMail(mailOptions);
      console.log(`Suspicious activity alert sent to ${email}`);
    } catch (error) {
      console.error('Failed to send suspicious activity alert:', error);
      // Don't throw error to avoid breaking the login flow
    }
  }

  /**
   * Send admin notification for suspicious activities
   */
  async sendAdminSecurityAlert(
    adminEmail: string,
    alertDetails: {
      type: 'ACCOUNT_BLOCKED' | 'UNAUTHORIZED_ADMIN_ACCESS' | 'MULTIPLE_FAILED_ATTEMPTS';
      userEmail: string;
      attempts: number;
      ipAddress?: string;
      userAgent?: string;
      timestamp: Date;
    }
  ): Promise<void> {
    const { type, userEmail, attempts, ipAddress, userAgent, timestamp } = alertDetails;
    
    const subject = `🚨 Admin Alert - ${type.replace(/_/g, ' ')}`;
    
    const mailOptions = {
      from: `"Cyberix Security Admin" <${config.email?.user || 'noreply@cyberix.com'}>`,
      to: adminEmail,
      subject: subject,
      html: this.getAdminSecurityAlertTemplate(type, userEmail, attempts, timestamp, ipAddress, userAgent)
    };

    try {
      await this.transporter.sendMail(mailOptions);
      console.log(`Admin security alert sent to ${adminEmail}`);
    } catch (error) {
      console.error('Failed to send admin security alert:', error);
    }
  }

  private getSuspiciousActivityEmailTemplate(
    title: string,
    description: string,
    actionRequired: string,
    email: string,
    attempts: number,
    blockedAt: Date,
    expiresAt: Date,
    remainingMinutes: number,
    ipAddress?: string,
    userAgent?: string
  ): string {
    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Alert - Cyberix Security</title>
        <style>
            body, table, td, a {
                -webkit-text-size-adjust: 100%;
                -ms-text-size-adjust: 100%;
            }
            table, td {
                border-collapse: collapse !important;
            }
            img {
                border: 0;
                line-height: 100%;
                text-decoration: none;
                -ms-interpolation-mode: bicubic;
            }
            body {
                margin: 0 !important;
                padding: 0 !important;
                width: 100% !important;
                height: 100% !important;
                background-color: #f9f9f9;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                color: #333;
            }
            .container {
                max-width: 600px;
                margin: 20px auto;
                background-color: #ffffff;
                border-radius: 12px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.08);
                overflow: hidden;
                border: 1px solid #e0e0e0;
            }
            .header {
                background-color: #d32f2f;
                color: white;
                padding: 20px;
                text-align: center;
            }
            .header h1 {
                margin: 0;
                font-size: 24px;
            }
            .content {
                padding: 30px;
            }
            .alert-box {
                background-color: #fff3e0;
                border-left: 4px solid #ff9800;
                padding: 15px;
                margin: 20px 0;
                border-radius: 4px;
            }
            .details-table {
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
                background-color: #f8f9fa;
                border-radius: 6px;
                overflow: hidden;
            }
            .details-table td {
                padding: 12px 15px;
                border-bottom: 1px solid #e9ecef;
            }
            .details-table td:first-child {
                font-weight: bold;
                color: #666;
                width: 40%;
                background-color: #f1f3f4;
            }
            .details-table td:last-child {
                color: #333;
            }
            .security-tips {
                background-color: #e8f5e8;
                border-left: 4px solid #4caf50;
                padding: 15px;
                margin: 20px 0;
                border-radius: 4px;
            }
            .security-tips h4 {
                color: #2e7d32;
                margin-top: 0;
            }
            .security-tips ul {
                color: #2e7d32;
                margin: 0;
                padding-left: 20px;
            }
            .footer {
                text-align: center;
                font-size: 12px;
                color: #999;
                border-top: 1px solid #eee;
                padding: 20px;
                background: #fafafa;
            }
            .countdown {
                font-size: 18px;
                font-weight: bold;
                color: #d32f2f;
                text-align: center;
                margin: 15px 0;
                padding: 10px;
                background-color: #ffebee;
                border-radius: 4px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔒 Cyberix Security Alert</h1>
            </div>
            
            <div class="content">
                <h2 style="color: #d32f2f; margin-top: 0;">${title}</h2>
                
                <p style="font-size: 16px; line-height: 1.5; color: #333;">
                    ${description}
                </p>

                <div class="countdown">
                    ⏰ Block expires in: ${remainingMinutes} minutes
                </div>

                <table class="details-table">
                    <tr>
                        <td>Email:</td>
                        <td>${email}</td>
                    </tr>
                    <tr>
                        <td>Failed Attempts:</td>
                        <td>${attempts}</td>
                    </tr>
                    <tr>
                        <td>IP Address:</td>
                        <td>${ipAddress || 'Unknown'}</td>
                    </tr>
                    <tr>
                        <td>Device:</td>
                        <td>${userAgent || 'Unknown'}</td>
                    </tr>
                    <tr>
                        <td>Blocked At:</td>
                        <td>${blockedAt.toLocaleString()}</td>
                    </tr>
                    <tr>
                        <td>Expires At:</td>
                        <td>${expiresAt.toLocaleString()}</td>
                    </tr>
                </table>

                <div class="alert-box">
                    <h4 style="color: #e65100; margin-top: 0;">Action Required:</h4>
                    <p style="margin: 0; color: #e65100;">${actionRequired}</p>
                </div>

                <div class="security-tips">
                    <h4>Security Tips:</h4>
                    <ul>
                        <li>Use a strong, unique password</li>
                        <li>Enable two-factor authentication if available</li>
                        <li>Never share your login credentials</li>
                        <li>Log out from shared devices</li>
                        <li>Contact support if you notice suspicious activity</li>
                    </ul>
                </div>

                <div style="text-align: center; margin-top: 30px;">
                    <p style="color: #666; margin-bottom: 15px;">Need help? Contact our support team:</p>
                    <a href="mailto:support@cyberix.com" style="background-color: #2196f3; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
                        Contact Support
                    </a>
                </div>
            </div>
            
            <div class="footer">
                <p style="margin: 0;">This is an automated security alert from Cyberix Security Platform.</p>
                <p style="margin: 5px 0 0 0;">If you did not attempt to login, please contact support immediately.</p>
            </div>
        </div>
    </body>
    </html>
    `;
  }

  private getAdminSecurityAlertTemplate(
    type: string,
    userEmail: string,
    attempts: number,
    timestamp: Date,
    ipAddress?: string,
    userAgent?: string
  ): string {
    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Admin Security Alert - Cyberix Security</title>
        <style>
            body, table, td, a {
                -webkit-text-size-adjust: 100%;
                -ms-text-size-adjust: 100%;
            }
            table, td {
                border-collapse: collapse !important;
            }
            body {
                margin: 0 !important;
                padding: 0 !important;
                width: 100% !important;
                height: 100% !important;
                background-color: #f9f9f9;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                color: #333;
            }
            .container {
                max-width: 600px;
                margin: 20px auto;
                background-color: #ffffff;
                border-radius: 12px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.08);
                overflow: hidden;
                border: 1px solid #e0e0e0;
            }
            .header {
                background-color: #d32f2f;
                color: white;
                padding: 20px;
                text-align: center;
            }
            .header h1 {
                margin: 0;
                font-size: 24px;
            }
            .content {
                padding: 30px;
            }
            .details-table {
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
                background-color: #f8f9fa;
                border-radius: 6px;
                overflow: hidden;
            }
            .details-table td {
                padding: 12px 15px;
                border-bottom: 1px solid #e9ecef;
            }
            .details-table td:first-child {
                font-weight: bold;
                color: #666;
                width: 40%;
                background-color: #f1f3f4;
            }
            .details-table td:last-child {
                color: #333;
            }
            .footer {
                text-align: center;
                font-size: 12px;
                color: #999;
                border-top: 1px solid #eee;
                padding: 20px;
                background: #fafafa;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔒 Admin Security Alert</h1>
            </div>
            
            <div class="content">
                <h2 style="color: #d32f2f; margin-top: 0;">Security Event Detected</h2>
                
                <p style="font-size: 16px; line-height: 1.5; color: #333;">
                    A security event has been detected on the Cyberix platform that requires your attention.
                </p>

                <table class="details-table">
                    <tr>
                        <td>Event Type:</td>
                        <td>${type.replace(/_/g, ' ')}</td>
                    </tr>
                    <tr>
                        <td>User Email:</td>
                        <td>${userEmail}</td>
                    </tr>
                    <tr>
                        <td>Failed Attempts:</td>
                        <td>${attempts}</td>
                    </tr>
                    <tr>
                        <td>IP Address:</td>
                        <td>${ipAddress || 'Unknown'}</td>
                    </tr>
                    <tr>
                        <td>User Agent:</td>
                        <td>${userAgent || 'Unknown'}</td>
                    </tr>
                    <tr>
                        <td>Timestamp:</td>
                        <td>${timestamp.toLocaleString()}</td>
                    </tr>
                </table>

                <div style="text-align: center; margin-top: 30px;">
                    <p style="color: #666; margin-bottom: 15px;">Review this event in the admin dashboard:</p>
                    <a href="${process.env.FRONTEND_URL || 'http://localhost:3000'}/admin/login-logs" style="background-color: #2196f3; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
                        View Admin Dashboard
                    </a>
                </div>
            </div>
            
            <div class="footer">
                <p style="margin: 0;">This is an automated security alert for Cyberix administrators.</p>
            </div>
        </div>
    </body>
    </html>
    `;
  }
}
