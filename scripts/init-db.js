const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const db = new sqlite3.Database('./secure_app.db');

console.log('🔧 Initializing database...');

db.serialize(async () => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      name TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      token_hash TEXT,
      expires_at DATETIME
    )
  `);

  const adminPassword = await bcrypt.hash('Admin123!', 12);

  db.run(
    `INSERT OR IGNORE INTO users (email, password_hash, role)
     VALUES (?, ?, 'admin')`,
    ['admin@example.com', adminPassword]
  );

  console.log('✅ Database initialized');
  db.close();
});
