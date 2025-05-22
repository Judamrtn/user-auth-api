const express = require('express');
const router = express.Router();
const pool = require('../db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

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

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  if (user.rows.length === 0) return res.status(401).json({ error: 'Invalid username' });

  const valid = await bcrypt.compare(password, user.rows[0].password);
  if (!valid) return res.status(401).json({ error: 'Invalid password' });

  const token = jwt.sign({ id: user.rows[0].id }, process.env.JWT_SECRET);
  res.json({ token });
});

module.exports = router;
