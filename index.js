import express from 'express';
import nodemailer from 'nodemailer';
import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';
import dotenv from 'dotenv';
import cors from 'cors';
import bcrypt from 'bcryptjs';

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors({
  origin:"https://sv-agency.vercel.app"
}));

// Supabase client initialization
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Route for sending reset password email
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    // Try to trigger the password reset flow via Supabase Auth (if email exists in auth)
    const { data: users,error: authError } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: `${process.env.FRONTEND_URL}/admin-reset-password`,  // Redirect URL after reset
    })
    if (users) {
      var userId = users.id;
      res.status(200).json({ message: 'Password reset link has been sent to your email.' });
    }

    // If there was an error (meaning the email may not be in Supabase Auth)
    if (authError) {
      // Check the custom 'users' table
      const { data: users, error: userError } = await supabase
        .from('users')
        .select('*')
        .eq('email', email);
      var userId = users.id
      if (userError || users.length === 0) {
        return res.status(404).json({ error: 'No user found with this email in both the authentication system and the users table.' });
      }


       // Generate a reset token and expiration time
    const resetToken = crypto.randomBytes(32).toString('hex');
    // Get the current time
const currentTime = new Date(); // Get the current date and time

// Set the expiration time to one hour later
const expirationTime = new Date(currentTime.getTime() + 60 * 60 * 1000); // Token expires in 1 hour

// Log the current and expiration times for debugging
console.log("Current Time:", currentTime);
console.log("Expiration Time:", expirationTime);
    // Save the reset token and expiration in your 'users' table
    const { error: updateError } = await supabase
      .from('users')
      .update({
        reset_token: resetToken,
        reset_token_expires_at: expirationTime.toISOString(), // Store as ISO string
      })
      .eq('email', email);

    if (updateError) throw updateError;

    // Send the reset password email using Nodemailer
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}&userId=${userId}`;
    
    await sendResetEmail(email, resetUrl);

    // If no errors, return success
    res.status(200).json({ message: 'Password reset link has been sent to your email.' });

    }

   
  } catch (error) {
    console.error('Error handling forgot password:', error);
    res.status(500).json({ error: 'An error occurred. Please try again later.' });
  }
});

app.post('/reset-password', async (req, res) => {
  const { token, newPassword, userId } = req.body;
 
  try {
     

      //  // Check if the user exists in Supabase Auth using the reset token
      //  const { data: usersAuth, error: authError } = await supabase.auth.api.getUserByCookie(req);

      //  if (usersAuth) {
      //    // User exists in Supabase Auth, reset the password using Supabase Auth
      //    const { error: resetError } = await supabase.auth.api.updateUser(usersAuth.id, {
      //      password: newPassword,
      //    });
   
      //    if (resetError) {
      //      return res.status(400).json({ error: 'Failed to reset password in Supabase Auth.' });
      //    }
   
      //    return res.status(200).json({ message: 'Your password has been reset successfully in Supabase Auth.' });
      //  }


    // Check if the user exists in the custom users table
    const { data: users, error: tokenError } = await supabase
      .from('users')
      .select('*')
      .eq('reset_token', token);

    if (tokenError || users.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired reset token.' });
    }

    // Check if the reset token has expired
    const expirationTime = new Date(users[0].reset_token_expires_at);
    const currentTime = new Date();
    if (currentTime > expirationTime) {
      return res.status(400).json({ error: 'Invalid or expired reset token.' });
    }

    // Hash the new password using bcrypt
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update the user's password hash in the custom users table
    const userEmail = users[0].email;
    const { error: updateError } = await supabase
      .from('users')
      .update({
        password: hashedPassword, // Update the password
        reset_token: null,              // Clear the reset token
        reset_token_expires_at: null,   // Clear the expiration time
      })
      .eq('email', userEmail);

    if (updateError) {
      return res.status(400).json({ error: 'Failed to update password in the users table.' });
    }

    // Verify the update by fetching the user again and comparing the passwords
    const { data: updatedUser, error: fetchError } = await supabase
      .from('users')
      .select('password')
      .eq('email', userEmail)
      .single();

    if (fetchError) {
      return res.status(500).json({ error: 'Failed to verify the updated user.' });
    }

    // Check if the password in the database matches the newly hashed password
    if (updatedUser.password === hashedPassword) {
      console.log('Password updated successfully.');
      return res.status(200).json({ message: 'Your password has been reset successfully in the users table.' });
    } else {
      console.log('Password update verification failed.');
      return res.status(400).json({ error: 'Password update failed in the users table.' });
    }

  } catch (error) {
    console.error('Error handling reset password:', error);
    res.status(500).json({ error: 'An error occurred. Please try again later.' });
  }
});

// Nodemailer configuration and send email function
const sendResetEmail = async (email, resetUrl) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: false, // true for 465, false for other ports
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const mailOptions = {
    from: `"Your Company" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Reset Your Password',
    text: `You requested a password reset. Click the link to reset your password: ${resetUrl}`,
    html: `
      <p>Hi,</p>
      <p>You requested a password reset. Click the link below to reset your password:</p>
      <a href="${resetUrl}">Reset Password</a>
      <p>If you did not request this, please ignore this email. The link will expire in 1 hour.</p>
    `,
  };

  await transporter.sendMail(mailOptions);
};

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
