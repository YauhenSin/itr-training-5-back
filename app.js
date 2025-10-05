const express = require('express');
const cors = require('cors');
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

app.use(cors());
app.use(express.json());

app.get('/main', (req, res) => {
  res.json({ message: 'hello world' });
});

// Get all users
app.get('/users', async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      select: userSelect
    });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create a new user
app.post('/users', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const user = await prisma.user.create({
      data: { name, email, password },
      select: userSelect
    });
    res.status(201).json(user);
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
