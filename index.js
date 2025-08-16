require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const Joi = require('joi');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();

// Middleware
app.use(express.json());
app.use(helmet());
app.use(morgan('dev'));
app.use(cors({
  origin: process.env.FRONTEND_ORIGIN ? process.env.FRONTEND_ORIGIN.split(',') : '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limit auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});
app.use(['/api/login', '/api/register', '/request-password-reset'], authLimiter);

// MongoDB Connection
const MONGO_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/portfolio';
const SECRET = process.env.SECRET_KEY || 'devSecret';

mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ Mongo error', err));

// Schemas
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

const projectSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  name: String,
  url: String
}, { timestamps: true });
const Project = mongoose.model('Project', projectSchema);

const todoSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  text: { type: String, required: true, trim: true, maxlength: 280 },
  done: { type: Boolean, default: false }
}, { timestamps: true });
const Todo = mongoose.model('Todo', todoSchema);

// Middleware for auth
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = { userId: decoded.userId || decoded.id, email: decoded.email };
    next();
  } catch (e) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

// ✅ Root route (Fix for Render showing "Cannot GET /")
app.get('/', (req, res) => {
  res.send('🚀 Backend Portfolio API is running successfully!');
});

// Contact demo
app.post('/api/contact', (req, res) => {
  const { name, email } = req.body || {};
  if (!name || !email) return res.status(400).json({ message: 'Name and email are required' });
  console.log('📩 Contact:', name, email);
  res.json({ message: 'Contact received' });
});

// ====================== AUTH ======================

app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

  const exists = await User.findOne({ email });
  if (exists) return res.status(400).json({ message: 'User already exists' });

  const hashed = await bcrypt.hash(password, 10);
  const user = await User.create({ name, email, password: hashed });
  res.json({ message: 'User registered successfully', id: user._id });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: 'Invalid email or password' });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(400).json({ message: 'Invalid email or password' });

  const token = jwt.sign({ userId: user._id, email: user.email }, SECRET, { expiresIn: '1h' });
  res.json({ token, name: user.name });
});

app.get('/me', authMiddleware, async (req, res) => {
  const user = await User.findById(req.user.userId).select('name email');
  res.json(user);
});

app.put('/profile', authMiddleware, async (req, res) => {
  const { email, password } = req.body || {};
  const user = await User.findById(req.user.userId);
  if (!user) return res.status(404).send('User not found');

  if (email) user.email = email;
  if (password) user.password = await bcrypt.hash(password, 10);
  await user.save();
  res.send('Profile updated');
});

// ====================== PROJECTS CRUD ======================
app.get('/user-projects', authMiddleware, async (req, res) => {
  res.json(await Project.find({ userId: req.user.userId }).sort({ createdAt: -1 }));
});

app.post('/user-projects', authMiddleware, async (req, res) => {
  const { name, url } = req.body || {};
  if (!name || !url) return res.status(400).send('Name and URL required');
  const project = await Project.create({ userId: req.user.userId, name, url });
  res.status(201).json(project);
});

app.put('/user-projects/:id', authMiddleware, async (req, res) => {
  const { name, url } = req.body || {};
  const proj = await Project.findOne({ _id: req.params.id, userId: req.user.userId });
  if (!proj) return res.status(404).send('Project not found');
  if (name) proj.name = name;
  if (url) proj.url = url;
  await proj.save();
  res.json(proj);
});

app.delete('/user-projects/:id', authMiddleware, async (req, res) => {
  const del = await Project.findOneAndDelete({ _id: req.params.id, userId: req.user.userId });
  if (!del) return res.status(404).send('Project not found');
  res.send('Deleted');
});

// ====================== TODOS CRUD ======================
app.get('/todos', authMiddleware, async (req, res) => {
  res.json(await Todo.find({ userId: req.user.userId }).sort({ createdAt: -1 }));
});

app.post('/todos', authMiddleware, async (req, res) => {
  const schema = Joi.object({ text: Joi.string().trim().min(1).max(280).required() });
  const { error, value } = schema.validate(req.body);
  if (error) return res.status(400).json({ message: error.message });
  const todo = await Todo.create({ userId: req.user.userId, text: value.text });
  res.status(201).json(todo);
});

app.put('/todos/:id', authMiddleware, async (req, res) => {
  const { text, done } = req.body || {};
  const todo = await Todo.findOne({ _id: req.params.id, userId: req.user.userId });
  if (!todo) return res.status(404).json({ message: 'Not found' });
  if (typeof text === 'string') todo.text = text.trim();
  if (typeof done === 'boolean') todo.done = done;
  await todo.save();
  res.json(todo);
});

app.delete('/todos/:id', authMiddleware, async (req, res) => {
  const deleted = await Todo.findOneAndDelete({ _id: req.params.id, userId: req.user.userId });
  if (!deleted) return res.status(404).json({ message: 'Not found' });
  res.sendStatus(204);
});

// ====================== PASSWORD RESET (Demo) ======================
const passwordResetTokens = new Map();
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

app.post('/request-password-reset', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).send('Email required');
  const user = await User.findOne({ email });
  if (!user) return res.status(404).send('User not found');

  const token = crypto.randomBytes(32).toString('hex');
  const expires = Date.now() + 3600000;
  passwordResetTokens.set(token, { userId: user._id, expires });

  const resetLink = (process.env.FRONTEND_RESET_URL || 'http://localhost:5500/reset-password.html') + `?token=${token}`;
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset',
      text: `Reset your password: ${resetLink}`
    });
    res.send('Password reset email sent');
  } catch (e) {
    console.error(e);
    res.status(500).send('Error sending email');
  }
});

app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body || {};
  const record = passwordResetTokens.get(token);
  if (!record) return res.status(400).send('Invalid or expired token');
  if (Date.now() > record.expires) {
    passwordResetTokens.delete(token);
    return res.status(400).send('Token expired');
  }
  const user = await User.findById(record.userId);
  if (!user) return res.status(404).send('User not found');
  user.password = await bcrypt.hash(newPassword, 10);
  await user.save();
  passwordResetTokens.delete(token);
  res.send('Password reset successfully');
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('❌ Error:', err);
  res.status(err.status || 500).json({ message: err.message || 'Server error' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 API running on port ${PORT}`));