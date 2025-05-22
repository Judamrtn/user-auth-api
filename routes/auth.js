const express = require('express');
const router = express.Router();
const pool = require('../db'); // PostgreSQL connection pool
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// Register a new user
router.post('/register', async (req, res) => {
  const { name, username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await pool.query(
      'INSERT INTO users (name, username, password) VALUES ($1, $2, $3) RETURNING id, name, username',
      [name, username, hashedPassword]
    );
    res.status(201).json({ user: newUser.rows[0] });
  } catch (err) {
    res.status(400).json({ error: 'Username already exists' });
  }
});

// Login user
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (user.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid username' });
    }

    const valid = await bcrypt.compare(password, user.rows[0].password);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    const token = jwt.sign({ id: user.rows[0].id }, process.env.JWT_SECRET);
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Get user by ID (excluding password)
router.get('/user/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const user = await pool.query('SELECT id, name, username FROM users WHERE id = $1', [id]);
    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Update user info
router.put('/user/:id', async (req, res) => {
  const { id } = req.params;
  const { name, username, password } = req.body;

  try {
    let hashedPassword = null;
    if (password) {
      hashedPassword = await bcrypt.hash(password, 10);
    }

    const updatedUser = await pool.query(
      `UPDATE users
       SET name = $1,
           username = $2,
           password = COALESCE($3, password)
       WHERE id = $4
       RETURNING id, name, username`,
      [name, username, hashedPassword, id]
    );

    if (updatedUser.rows.length === 0) {
      return res.status(404).json({ error: 'User not found or no changes made' });
    }

    res.json(updatedUser.rows[0]);
  } catch (err) {
    res.status(400).json({ error: 'Could not update user (maybe username already taken)' });
  }
});

module.exports = router;
