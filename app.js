const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
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

const requiredEnvVars = ['JWT_SECRET', 'FRONTEND_ORIGIN'];
requiredEnvVars.forEach((name) => {
  if (!process.env[name]) {
    throw new Error(`Environment variable ${name} is required`);
  }
});

const { JWT_SECRET, FRONTEND_ORIGIN } = process.env;
const TOKEN_EXPIRY = '7d';

app.use(cors({
  origin: FRONTEND_ORIGIN
}));
app.use(express.json());
const generateToken = (userId) =>
  jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });

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

    const token = generateToken(user.id);

    res.status(201).json({ token, user });
  } catch (error) {
    if (error.code === 'P2002') {
      return res.status(409).json({ error: 'A user with that email already exists.' });
    }
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
