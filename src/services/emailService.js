const nodemailer = require('nodemailer');

class EmailService {
  constructor() {
    // Create transporter based on environment
    if (process.env.NODE_ENV === 'production') {
      // Production: Use real SMTP service
      this.transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT) || 587,
        secure: process.env.SMTP_SECURE === 'true', // true for 465, false for other ports
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASSWORD,
        },
      });
    } else {
      // Development: Use Ethereal email (fake SMTP service)
      // You can view emails at https://ethereal.email/
      this.transporter = nodemailer.createTransport({
        host: 'smtp.ethereal.email',
        port: 587,
        secure: false,
        auth: {
          user: process.env.SMTP_USER || 'ethereal.user@ethereal.email',
          pass: process.env.SMTP_PASSWORD || 'ethereal-password',
        },
      });
    }
  }

  /**
   * Send email verification
   */
  async sendVerificationEmail(email, token, userName) {
    const verificationUrl = `${process.env.APP_URL}/verify-email?token=${token}`;

    const mailOptions = {
      from: process.env.SMTP_FROM || '"Auth Service" <noreply@authservice.com>',
      to: email,
      subject: 'Verify Your Email Address',
      html: this.getVerificationEmailTemplate(userName, verificationUrl),
      text: `Hi ${userName},\n\nPlease verify your email by clicking this link: ${verificationUrl}\n\nThis link will expire in 24 hours.\n\nIf you didn't create an account, please ignore this email.`,
    };

    try {
      const info = await this.transporter.sendMail(mailOptions);
      console.log('Verification email sent:', info.messageId);
      
      // In development, log the preview URL
      if (process.env.NODE_ENV !== 'production') {
        console.log('Preview URL:', nodemailer.getTestMessageUrl(info));
      }
      
      return info;
    } catch (error) {
      console.error('Error sending verification email:', error);
      throw new Error('Failed to send verification email');
    }
  }

  /**
   * Send password reset email
   */
  async sendPasswordResetEmail(email, token, userName) {
    const resetUrl = `${process.env.APP_URL}/reset-password?token=${token}`;

    const mailOptions = {
      from: process.env.SMTP_FROM || '"Auth Service" <noreply@authservice.com>',
      to: email,
      subject: 'Reset Your Password',
      html: this.getPasswordResetEmailTemplate(userName, resetUrl),
      text: `Hi ${userName},\n\nYou requested to reset your password. Click this link to reset it: ${resetUrl}\n\nThis link will expire in 1 hour.\n\nIf you didn't request this, please ignore this email.`,
    };

    try {
      const info = await this.transporter.sendMail(mailOptions);
      console.log('Password reset email sent:', info.messageId);
      
      if (process.env.NODE_ENV !== 'production') {
        console.log('Preview URL:', nodemailer.getTestMessageUrl(info));
      }
      
      return info;
    } catch (error) {
      console.error('Error sending password reset email:', error);
      throw new Error('Failed to send password reset email');
    }
  }

  /**
   * Send welcome email (after verification)
   */
  async sendWelcomeEmail(email, userName) {
    const mailOptions = {
      from: process.env.SMTP_FROM || '"Auth Service" <noreply@authservice.com>',
      to: email,
      subject: 'Welcome to Auth Service!',
      html: this.getWelcomeEmailTemplate(userName),
      text: `Hi ${userName},\n\nWelcome to Auth Service! Your email has been verified and your account is now active.\n\nThank you for joining us!`,
    };

    try {
      const info = await this.transporter.sendMail(mailOptions);
      console.log('Welcome email sent:', info.messageId);
      return info;
    } catch (error) {
      console.error('Error sending welcome email:', error);
      // Don't throw error for welcome email - it's not critical
    }
  }

  /**
   * Email verification template
   */
  getVerificationEmailTemplate(userName, verificationUrl) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
          .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
          .button { display: inline-block; padding: 12px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
          .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔐 Email Verification</h1>
          </div>
          <div class="content">
            <h2>Hi ${userName}!</h2>
            <p>Thank you for registering with Auth Service. Please verify your email address to activate your account.</p>
            <p style="text-align: center;">
              <a href="${verificationUrl}" class="button">Verify Email Address</a>
            </p>
            <p>Or copy and paste this link in your browser:</p>
            <p style="word-break: break-all; background: white; padding: 10px; border-radius: 5px;">${verificationUrl}</p>
            <p><strong>This link will expire in 24 hours.</strong></p>
            <p>If you didn't create an account, please ignore this email.</p>
          </div>
          <div class="footer">
            <p>© 2026 Auth Service. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Password reset email template
   */
  getPasswordResetEmailTemplate(userName, resetUrl) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
          .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
          .button { display: inline-block; padding: 12px 30px; background: #f5576c; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
          .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔑 Password Reset</h1>
          </div>
          <div class="content">
            <h2>Hi ${userName}!</h2>
            <p>You requested to reset your password. Click the button below to create a new password.</p>
            <p style="text-align: center;">
              <a href="${resetUrl}" class="button">Reset Password</a>
            </p>
            <p>Or copy and paste this link in your browser:</p>
            <p style="word-break: break-all; background: white; padding: 10px; border-radius: 5px;">${resetUrl}</p>
            <p><strong>This link will expire in 1 hour.</strong></p>
            <p>If you didn't request this, please ignore this email and your password will remain unchanged.</p>
          </div>
          <div class="footer">
            <p>© 2026 Auth Service. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Welcome email template
   */
  getWelcomeEmailTemplate(userName) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
          .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
          .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🎉 Welcome!</h1>
          </div>
          <div class="content">
            <h2>Hi ${userName}!</h2>
            <p>Welcome to Auth Service! Your email has been verified and your account is now fully activated.</p>
            <p>You can now enjoy all the features of our platform.</p>
            <p>If you have any questions or need assistance, feel free to contact our support team.</p>
            <p>Thank you for joining us!</p>
          </div>
          <div class="footer">
            <p>© 2026 Auth Service. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Verify transporter configuration
   */
  async verifyConnection() {
    try {
      await this.transporter.verify();
      console.log('✓ Email service is ready to send emails');
      return true;
    } catch (error) {
      console.error('✗ Email service error:', error);
      return false;
    }
  }
}

module.exports = new EmailService();
