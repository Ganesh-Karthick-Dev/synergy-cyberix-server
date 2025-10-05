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
                        <span class="credential-label">Username:</span>
                        <span class="credential-value">${username}</span>
                    </div>
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
}
