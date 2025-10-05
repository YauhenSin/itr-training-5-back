const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { PrismaClient } = require('@prisma/client');

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;

const userSelect = {
  id: true,
  name: true,
  email: true,
  status: true,
  registrationTime: true
};

const requiredEnvVars = [
  'JWT_SECRET',
  'FRONTEND_ORIGIN',
  'SMTP_HOST',
  'SMTP_PORT',
  'SMTP_USER',
  'SMTP_PASSWORD',
  'EMAIL_FROM',
  'ACTIVATION_LINK_BASE'
];
requiredEnvVars.forEach((name) => {
  if (!process.env[name]) {
    throw new Error(`Environment variable ${name} is required`);
  }
});

const {
  JWT_SECRET,
  FRONTEND_ORIGIN,
  SMTP_HOST,
  SMTP_PORT,
  SMTP_USER,
  SMTP_PASSWORD,
  EMAIL_FROM,
  ACTIVATION_LINK_BASE
} = process.env;
const TOKEN_EXPIRY = '7d';

app.use(cors({
  origin: FRONTEND_ORIGIN
}));
app.use(express.json());
const generateToken = (userId) =>
  jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });

const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: Number(SMTP_PORT),
  secure: Number(SMTP_PORT) === 465,
  auth: {
    user: SMTP_USER,
    pass: SMTP_PASSWORD
  }
});

const createActivationToken = async (userId) => {
  const tokenValue = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24); // 24 hours

  await prisma.activationToken.create({
    data: {
      token: tokenValue,
      userId,
      expiresAt
    }
  });

  return tokenValue;
};

const buildActivationUrl = (token) => `${ACTIVATION_LINK_BASE}?token=${token}`;

const sendActivationEmail = async ({ email, name }, token) => {
  const activationUrl = buildActivationUrl(token);

  try {
    await transporter.sendMail({
      from: EMAIL_FROM,
      to: email,
      subject: 'Activate your account',
      text: `Hi ${name},\n\nThanks for registering. Please activate your account using the link below:\n${activationUrl}\n\nIf you did not create this account, please ignore this email.`,
      html: `<p>Hi ${name},</p>
             <p>Thanks for registering. Please activate your account using the link below:</p>
             <p><a href="${activationUrl}">Activate Account</a></p>
             <p>If you did not create this account, please ignore this email.</p>`
    });
  } catch (error) {
    console.error('Failed to send activation email', { email, error });
    throw error;
  }
};

const requireAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.sub;
    return next();
  } catch (error) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
};

app.get('/main', (req, res) => {
  res.json({ message: 'hello world' });
});

app.get('/auth/me', requireAuth, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.userId },
      select: userSelect
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ authenticated: true, user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/auth/logout', (_req, res) => {
  res.status(204).end();
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    if (user.status !== 'ACTIVE') {
      return res.status(403).json({ error: 'Account is not activated. Please check your email.' });
    }

    const token = generateToken(user.id);

    res.json({
      message: 'Logged in successfully.',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/users', requireAuth, async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      select: userSelect
    });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/users', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: { name, email, password: hashedPassword },
      select: userSelect
    });
    try {
      const activationToken = await createActivationToken(user.id);
      await sendActivationEmail(user, activationToken);
      const activationUrl = buildActivationUrl(activationToken);
      return res.status(201).json({
        message: 'Registration successful. Please check your email to activate your account.',
        activationUrl
      });
    } catch (emailError) {
      console.error('Activation email dispatch failed; rolling back user creation', {
        userId: user.id,
        email: user.email,
        error: emailError
      });
      await prisma.activationToken.deleteMany({ where: { userId: user.id } });
      await prisma.user.delete({ where: { id: user.id } });
      return res.status(500).json({ error: 'Unable to send activation email. Please try again later.' });
    }
  } catch (error) {
    if (error.code === 'P2002') {
      return res.status(409).json({ error: 'A user with that email already exists.' });
    }
    res.status(400).json({ error: error.message });
  }
});

app.post('/auth/activate', async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ error: 'Activation token is required.' });
    }

    const activationToken = await prisma.activationToken.findUnique({
      where: { token },
      include: {
        user: {
          select: userSelect
        }
      }
    });

    if (!activationToken) {
      return res.status(404).json({ error: 'Activation link is invalid.' });
    }

    if (activationToken.usedAt) {
      return res.status(400).json({ error: 'Activation link has already been used.' });
    }

    if (activationToken.expiresAt < new Date()) {
      return res.status(400).json({ error: 'Activation link has expired.' });
    }

    const updatedUser = await prisma.user.update({
      where: { id: activationToken.userId },
      data: { status: 'ACTIVE' },
      select: userSelect
    });

    await prisma.activationToken.update({
      where: { id: activationToken.id },
      data: { usedAt: new Date() }
    });

    const authToken = generateToken(updatedUser.id);

    res.json({
      message: 'Account activated successfully.',
      token: authToken,
      user: updatedUser
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

process.on('SIGINT', async () => {
  await prisma.$disconnect();
  process.exit(0);
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
