import Mailgen from "mailgen";
import nodemailer from "nodemailer";

/*
 * Mail utilities for the Task Manager App
 *
 * This module provides a simple wrapper around Mailgen (email templating)
 * and nodemailer (SMTP transport) for sending transactional emails such as
 * account verification and password reset messages.
 *
 * Exports:
 * - sendEmail(options) : sends an email using MAILTRAP SMTP env vars
 * - emailVerificationMailGenContent(username, verificationUrl) : builds
 *      Mailgen content for an email verification message
 * - forgotPasswordMailGenContent(username, passwordResetUrl) : builds
 *      Mailgen content for a password reset message
 */

/**
 * Send an email using Mailgen and nodemailer.
 *
 * @param {Object} options - options for the email send
 * @param {string} options.email - recipient email address
 * @param {string} options.subject - subject line for the email
 * @param {Object} options.mailgentContent - Mailgen content object used to
 *                                         generate HTML and plaintext bodies
 *
 * Note: This function expects SMTP connection details to be provided via
 * environment variables: MAILTRAP_SMTP_HOST, MAILTRAP_SMTP_PORT,
 * MAILTRAP_SMTP_USERNAME, MAILTRAP_SMTP_PASSWORD. It will log an error if
 * sending fails but won't throw (silent failure approach used intentionally).
 */
const sendEmail = async (options) => {
  // Configure Mailgen instance with default theme/product details.
  // Mailgen generates both HTML and plaintext email bodies using the
  // structured content objects returned by the helper functions below.
  const mailGenerator = new Mailgen({
    theme: "default",
    product: {
      name: "Task Manager App",
      link: "https://taskmanagerlink.com",
    },
  });
  // Generate both plaintext and HTML versions from the supplied content.
  // The `options.mailgentContent` parameter must be a Mailgen-compatible
  // content object (see the helper functions below for examples).
  const emailTextual = mailGenerator.generatePlaintext(options.mailgentContent);
  const emailHtml = mailGenerator.generate(options.mailgentContent);

  // Create an SMTP transporter from env vars. This project uses Mailtrap
  // credentials (development/testing) but the same env var pattern can be
  // swapped for other SMTP providers in production.
  const transporter = nodemailer.createTransport({
    host: process.env.MAILTRAP_SMTP_HOST,
    port: process.env.MAILTRAP_SMTP_PORT,
    auth: {
      user: process.env.MAILTRAP_SMTP_USERNAME,
      pass: process.env.MAILTRAP_SMTP_PASSWORD,
    },
  });

  // Compose the message object nodemailer expects.
  const mail = {
    from: "mail.taskmanager@example.com",
    to: options.email,
    subject: options.subject,
    text: emailTextual,
    html: emailHtml,
  };

  try {
    await transporter.sendMail(mail);
  } catch (error) {
    // Log the error but avoid blowing up the request flow. This makes the
    // email sending best-effort and avoids exposing mail failures to callers.
    console.error(
      "Email service failed silently. Make sure you have provided your MAILTRAP credentials in .env file",
    );
    console.error(error);
  }
};

/**
 * Build Mailgen content for an email verification message.
 *
 * @param {string} username - recipient user's display name
 * @param {string} verificationUrl - URL the user should click to verify
 * @returns {Object} Mailgen content object that can be passed to Mailgen
 *                   to produce email HTML/plaintext
 */
const emailVerificationMailGenContent = (username, verificationUrl) => {
  return {
    body: {
      name: username,
      // Short introduction paragraph visible at top of the email
      intro: "Welcome to our App! We're excited to have you onboard.",
      // Primary CTA that points users to the verification link
      action: {
        instructions:
          "To verify your email please click on the following button.",
        button: {
          color: "#22BC66",
          text: "Verify your email",
          link: verificationUrl,
        },
      },
      // Closing line for support/contact instructions
      outro:
        "Need help, or have questions? Just reply to this email, we'd love to help.",
    },
  };
};

/**
 * Build Mailgen content for a password reset email.
 *
 * @param {string} username - recipient user's display name
 * @param {string} passwordResetUrl - URL the user should click to reset
 * @returns {Object} Mailgen content object used to generate the email
 */
const forgotPasswordMailGenContent = (username, passwordResetUrl) => {
  return {
    body: {
      name: username,
      // Explains why the email was sent
      intro: "We got a request to reset the password of your account",
      // Primary CTA for resetting the password
      action: {
        instructions:
          "To reset your password click on the following button or link.",
        button: {
          color: "#22BC66",
          text: "Reset Password",
          link: passwordResetUrl,
        },
      },
      // Support instructions at the bottom
      outro:
        "Need help, or have questions? Just reply to this email, we'd love to help.",
    },
  };
};

export {
  emailVerificationMailGenContent,
  forgotPasswordMailGenContent,
  sendEmail,
};
