// TASK MANAGEMENT - EXPRESS


import express from 'express';
import fs from 'fs';
import path from 'path';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

const app = express();
const PORT = 5000;

// Use an environment variable 
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret_key_change_me';

// -------------------- Core Middleware --------------------
app.use(express.json());

// Logger middleware: logs method, URL, timestamp
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.originalUrl}`);
  next();
});

// -------------------- Persistence --------------------
// Tasks are stored in tasks.json for persistence across restarts
const DATA_FILE = path.join(process.cwd(), 'tasks.json');

function loadTasks() {
  if (!fs.existsSync(DATA_FILE)) return [];
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf-8');
    return JSON.parse(raw || '[]');
  } catch (err) {
    console.error('Failed to read tasks.json:', err);
    return [];
  }
}

function saveTasks(tasks) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(tasks, null, 2), 'utf-8');
  } catch (err) {
    console.error('Failed to write tasks.json:', err);
  }
}

// In-memory store backed by file
let tasks = loadTasks();
let nextId = tasks.length ? Math.max(...tasks.map(t => t.id)) + 1 : 1;

// -------------------- Validation Middleware --------------------
const ALLOWED_STATUSES = ['pending', 'in-progress', 'completed'];

function validateTask(req, res, next) {
  const { title, description, status } = req.body;

  if (req.method === 'POST') {
    if (!title || !description) {
      return res.status(400).json({
        success: false,
        message: 'Title and description are required'
      });
    }
  }

  if (status && !ALLOWED_STATUSES.includes(status)) {
    return res.status(400).json({
      success: false,
      message: `Invalid status. Allowed: ${ALLOWED_STATUSES.join(', ')}`
    });
  }

  next();
}

// -------------------- Auth --------------------
const users = []; // simple in-memory user store: { id, username, passwordHash }

function authRequired(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Missing token'
    });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      success: false,
      message: 'Invalid or expired token'
    });
  }
}

// Register
app.post('/auth/register', async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: 'Username and password required'
    });
  }

  if (users.find(u => u.username === username)) {
    return res.status(400).json({
      success: false,
      message: 'User already exists'
    });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const user = { id: users.length + 1, username, passwordHash };
  users.push(user);

  res.status(201).json({
    success: true,
    message: 'User registered',
    data: { id: user.id, username: user.username }
  });
});

// Login
app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body || {};

  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).json({
      success: false,
      message: 'Invalid credentials'
    });
  }

  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) {
    return res.status(401).json({
      success: false,
      message: 'Invalid credentials'
    });
  }

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '2h' });

  res.json({
    success: true,
    message: 'Login successful',
    data: { token }
  });
});

// -------------------- Routes: Tasks --------------------

// GET /tasks - list all tasks with sorting
app.get('/tasks', (req, res) => {
  const { status, sort } = req.query;
  let results = [...tasks];

  if (status) {
    results = results.filter(t => t.status === status);
  }

  if (sort === 'asc' || sort === 'desc') {
    results.sort((a, b) => {
      const da = new Date(a.createdAt).getTime();
      const db = new Date(b.createdAt).getTime();
      return sort === 'asc' ? da - db : db - da;
    });
  }

  res.json({
    success: true,
    message: 'Tasks retrieved successfully',
    data: results
  });
});

// GET /tasks/:id - retrieve single task by id
app.get('/tasks/:id', (req, res) => {
  const task = tasks.find(t => t.id == req.params.id);

  if (!task) {
    return res.status(404).json({
      success: false,
      message: 'Task not found'
    });
  }

  res.json({
    success: true,
    message: 'Task retrieved successfully',
    data: task
  });
});

// POST /tasks - create new task (auth required)
app.post('/tasks', authRequired, validateTask, (req, res) => {
  const { title, description, status } = req.body;

  const newTask = {
    id: nextId++,
    title,
    description,
    status: status || 'pending',
    createdAt: new Date().toISOString()
  };

  tasks.push(newTask);
  saveTasks(tasks);

  res.status(201).json({
    success: true,
    message: 'Task created successfully',
    data: newTask
  });
});

// PUT /tasks/:id - update task (auth required)
app.put('/tasks/:id', authRequired, validateTask, (req, res) => {
  const index = tasks.findIndex(t => t.id == parseInt(req.params.id));

  if (index === -1) {
    return res.status(404).json({
      success: false,
      message: 'Task not found'
    });
  }

  const { title, description, status } = req.body;

  tasks[index] = {
    ...tasks[index],
    title: title ?? tasks[index].title,
    description: description ?? tasks[index].description,
    status: status ?? tasks[index].status
  };

  saveTasks(tasks);

  res.json({
    success: true,
    message: 'Task updated successfully',
    data: tasks[index]
  });
});

// DELETE /tasks/:id - delete task (auth required)
app.delete('/tasks/:id', authRequired, (req, res) => {
  const id = parseInt(req.params.id);
  const index = tasks.findIndex(t => t.id === id);

  if (index === -1) {
    return res.status(404).json({
      success: false,
      message: 'Task not found'
    });
  }

  const deletedTask = tasks.splice(index, 1)[0];
  saveTasks(tasks);

  res.json({
    success: true,
    message: 'Task deleted successfully',
    data: deletedTask
  });
});

// -------------------- Error Handler --------------------
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    message: 'Internal server error'
  });
});

// -------------------- Start Server --------------------
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
