const express = require('express');
const router = express.Router();
const pool = require('../db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// Middleware to verify token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// REGISTER
router.post('/register', async (req, res) => {
  const { name, username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const newUser = await pool.query(
      'INSERT INTO users (name, username, password) VALUES ($1, $2, $3) RETURNING *',
      [name, username, hashedPassword]
    );
    res.status(201).json({ user: newUser.rows[0] });
  } catch (err) {
    res.status(400).json({ error: 'Username already exists' });
  }
});

// LOGIN
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  if (user.rows.length === 0) return res.status(401).json({ error: 'Invalid username' });

  const valid = await bcrypt.compare(password, user.rows[0].password);
  if (!valid) return res.status(401).json({ error: 'Invalid password' });

  const token = jwt.sign({ id: user.rows[0].id }, process.env.JWT_SECRET);
  res.json({ token });
});

// UPDATE USER
router.put('/update', authenticateToken, async (req, res) => {
  const { name, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const updated = await pool.query(
      'UPDATE users SET name = $1, password = $2 WHERE id = $3 RETURNING *',
      [name, hashedPassword, req.user.id]
    );
    res.json({ user: updated.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Update failed' });
  }
});

// DELETE USER
router.delete('/delete', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [req.user.id]);
    res.json({ message: 'User deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Delete failed' });
  }
});

module.exports = router;
