// edge-functions/auth.js
import { createClient } from '@sanity/client';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import validator from 'validator';
import nodemailer from 'nodemailer';
import rateLimit from 'express-rate-limit';

const sanityClient = createClient({
  projectId: 'your-project-id',
  dataset: 'your-dataset',
  useCdn: false,
  token: process.env.SANITY_API_TOKEN
});

const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;

// Rate limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

// Email transporter
const transporter = nodemailer.createTransport({
  // Configure your email service here
});

// Helper function to set secure cookie
const setSecureCookie = (res, name, value, options = {}) => {
  res.cookie(name, value, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: options.maxAge || 24 * 60 * 60 * 1000, // 24 hours by default
    ...options
  });
};

// Helper function for input sanitization
const sanitizeInput = (input) => {
  return validator.escape(input.trim());
};

export async function signUp(req, res) {
  limiter(req, res, async () => {
    const { email, password } = req.body;
    
    try {
      if (!validator.isEmail(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
      }

      if (!validator.isLength(password, { min: 8 })) {
        return res.status(400).json({ error: 'Password must be at least 8 characters long' });
      }

      const sanitizedEmail = sanitizeInput(email);

      const existingUser = await sanityClient.fetch(`*[_type == "user" && email == $email][0]`, { email: sanitizedEmail });
      if (existingUser) {
        return res.status(400).json({ error: 'User already exists' });
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      const verificationToken = jwt.sign({ email: sanitizedEmail }, JWT_SECRET, { expiresIn: '1d' });

      const newUser = await sanityClient.create({
        _type: 'user',
        email: sanitizedEmail,
        hashedPassword,
        salt,
        isVerified: false,
        verificationToken,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      });

      // Send verification email
      await transporter.sendMail({
        to: sanitizedEmail,
        subject: 'Verify your email',
        html: `Click <a href="${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}">here</a> to verify your email.`
      });

      res.status(201).json({ message: 'User created. Please check your email to verify your account.' });
    } catch (error) {
      console.error('Error in signUp:', error);
      res.status(500).json({ error: 'Error creating user' });
    }
  });
}

export async function verifyEmail(req, res) {
  const { token } = req.query;

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await sanityClient.fetch(`*[_type == "user" && email == $email][0]`, { email: decoded.email });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.isVerified) {
      return res.status(400).json({ error: 'Email already verified' });
    }

    if (user.verificationToken !== token) {
      return res.status(400).json({ error: 'Invalid verification token' });
    }

    await sanityClient
      .patch(user._id)
      .set({ isVerified: true, verificationToken: null })
      .commit();

    res.json({ message: 'Email verified successfully' });
  } catch (error) {
    console.error('Error in verifyEmail:', error);
    res.status(400).json({ error: 'Invalid or expired token' });
  }
}

export async function login(req, res) {
  limiter(req, res, async () => {
    const { email, password } = req.body;
    
    try {
      const sanitizedEmail = sanitizeInput(email);

      const user = await sanityClient.fetch(`*[_type == "user" && email == $email][0]`, { email: sanitizedEmail });
      if (!user) {
        return res.status(400).json({ error: 'Invalid credentials' });
      }

      if (!user.isVerified) {
        return res.status(400).json({ error: 'Please verify your email before logging in' });
      }

      const isMatch = await bcrypt.compare(password, user.hashedPassword);
      if (!isMatch) {
        return res.status(400).json({ error: 'Invalid credentials' });
      }

      const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '15m' });
      const refreshToken = jwt.sign({ userId: user._id }, REFRESH_SECRET, { expiresIn: '7d' });

      await sanityClient
        .patch(user._id)
        .set({ refreshToken })
        .commit();

      setSecureCookie(res, 'token', token, { maxAge: 15 * 60 * 1000 }); // 15 minutes
      setSecureCookie(res, 'refreshToken', refreshToken, { maxAge: 7 * 24 * 60 * 60 * 1000 }); // 7 days

      res.json({ message: 'Logged in successfully' });
    } catch (error) {
      console.error('Error in login:', error);
      res.status(500).json({ error: 'Error logging in' });
    }
  });
}

export async function refreshToken(req, res) {
  const { refreshToken } = req.cookies;

  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token not found' });
  }

  try {
    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
    const user = await sanityClient.fetch(`*[_type == "user" && _id == $userId][0]`, { userId: decoded.userId });

    if (!user || user.refreshToken !== refreshToken) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    const newToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '15m' });
    setSecureCookie(res, 'token', newToken, { maxAge: 15 * 60 * 1000 }); // 15 minutes

    res.json({ message: 'Token refreshed successfully' });
  } catch (error) {
    console.error('Error in refreshToken:', error);
    res.status(401).json({ error: 'Invalid refresh token' });
  }
}

export async function logout(req, res) {
  const { refreshToken } = req.cookies;

  if (refreshToken) {
    try {
      const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
      await sanityClient
        .patch(decoded.userId)
        .unset(['refreshToken'])
        .commit();
    } catch (error) {
      console.error('Error in logout:', error);
    }
  }

  res.clearCookie('token');
  res.clearCookie('refreshToken');
  res.json({ message: 'Logged out successfully' });
}

export async function updatePassword(req, res) {
  const { currentPassword, newPassword } = req.body;
  const { userId } = req.user; // Assuming you have middleware to extract user from token
  
  try {
    if (!validator.isLength(newPassword, { min: 8 })) {
      return res.status(400).json({ error: 'New password must be at least 8 characters long' });
    }

    const user = await sanityClient.fetch(`*[_type == "user" && _id == $userId][0]`, { userId });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const isMatch = await bcrypt.compare(currentPassword, user.hashedPassword);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid current password' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    await sanityClient
      .patch(userId)
      .set({ hashedPassword, salt, updatedAt: new Date().toISOString() })
      .commit();

    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error('Error in updatePassword:', error);
    res.status(500).json({ error: 'Error updating password' });
  }
}

export async function resetPassword(req, res) {
  const { email } = req.body;
  
  try {
    const sanitizedEmail = sanitizeInput(email);

    const user = await sanityClient.fetch(`*[_type == "user" && email == $email][0]`, { email: sanitizedEmail });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const resetToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });

    await sanityClient
      .patch(user._id)
      .set({ resetToken })
      .commit();

    // Send password reset email
    await transporter.sendMail({
      to: sanitizedEmail,
      subject: 'Reset your password',
      html: `Click <a href="${process.env.FRONTEND_URL}/reset-password?token=${resetToken}">here</a> to reset your password.`
    });

    res.json({ message: 'Password reset instructions sent to your email' });
  } catch (error) {
    console.error('Error in resetPassword:', error);
    res.status(500).json({ error: 'Error initiating password reset' });
  }
}
