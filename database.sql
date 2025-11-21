-- ExpenseEye SQLite schema + seed data (improved + views & trigger)
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;        -- faster concurrency for local testing
PRAGMA synchronous = NORMAL;     -- balanced durability for a demo

BEGIN TRANSACTION;

-- =======================
-- users table
-- =======================
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE CHECK (length(trim(username)) >= 3),
  email TEXT NOT NULL UNIQUE CHECK (instr(email, '@') > 1),
  password_hash TEXT NOT NULL,              -- store a salted hash (prefer bcrypt/argon2)
  salt TEXT NOT NULL,                       -- stored salt (if using legacy hashing)
  created_at TIMESTAMP NOT NULL DEFAULT (datetime('now')),
  last_login TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- =======================
-- categories table
-- =======================
CREATE TABLE IF NOT EXISTS categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE CHECK (length(trim(name)) > 0),
  description TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_categories_name ON categories(name);

-- =======================
-- expenses table
-- =======================
CREATE TABLE IF NOT EXISTS expenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  amount REAL NOT NULL CHECK (amount >= 0),
  category_id INTEGER,                         -- optional: allow uncategorized expenses
  note TEXT,
  date DATE NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY(category_id) REFERENCES categories(id) ON DELETE SET NULL ON UPDATE CASCADE
);

-- Useful indexes for queries (user's monthly/dated queries, category lookups)
CREATE INDEX IF NOT EXISTS idx_exp_user_date ON expenses(user_id, date);
CREATE INDEX IF NOT EXISTS idx_exp_category ON expenses(category_id);
CREATE INDEX IF NOT EXISTS idx_exp_user_amount ON expenses(user_id, amount);

-- =======================
-- Seed categories
-- =======================
INSERT OR IGNORE INTO categories (name, description) VALUES
  ('Food',    'Meals, groceries, snacks'),
  ('Travel',  'Transport & commuting'),
  ('Bills',   'Utilities & subscriptions'),
  ('Shopping','Personal purchases'),
  ('Misc',    'Other miscellaneous expenses');

-- =======================
-- Demo user (username: demo, password: password)
-- =======================
/*
  NOTE (important):
  - For production use: DO NOT use plain SHA256 for password storage.
    Use a slow, adaptive algorithm like bcrypt, scrypt, or Argon2 with a per-user salt.
*/
INSERT OR IGNORE INTO users (username, email, password_hash, salt)
VALUES (
  'demo',
  'demo@example.com',
  '4f36462dbb4b35db8641214e07cb5a5881986ad184350bf12601431ee9aa5c11',
  'salt123'
);

-- =======================
-- Sample expenses for demo user
-- =======================
INSERT INTO expenses (user_id, amount, category_id, note, date)
VALUES
  ((SELECT id FROM users WHERE username='demo'), 250.00,  (SELECT id FROM categories WHERE name='Food'),     'Lunch at cafe',       '2025-11-18'),
  ((SELECT id FROM users WHERE username='demo'), 1200.50, (SELECT id FROM categories WHERE name='Bills'),    'Electricity bill',    '2025-11-10'),
  ((SELECT id FROM users WHERE username='demo'), 499.99,  (SELECT id FROM categories WHERE name='Shopping'), 'Shoes',               '2025-10-30');

-- =======================
-- Trigger: update last_login (helper)
-- =======================
-- Note: it's recommended to update last_login from application code when a user logs in:
--   UPDATE users SET last_login = datetime('now') WHERE id = ?;
-- This trigger is included as a no-op placeholder and demonstrates where DB-side logic could live.
CREATE TRIGGER IF NOT EXISTS trg_users_touch_last_login
AFTER UPDATE OF last_login ON users
BEGIN
  -- intentional no-op: placeholder for instrumentation
  SELECT NEW.id;
END;

-- =======================
-- Read-only Views for reporting (dashboard helpers)
-- =======================
-- Monthly summary per user (YYYY-MM)
CREATE VIEW IF NOT EXISTS vw_monthly_summary AS
SELECT
  user_id,
  strftime('%Y-%m', date) AS month,
  COUNT(*) AS tx_count,
  SUM(amount) AS total_amount,
  AVG(amount) AS avg_amount
FROM expenses
GROUP BY user_id, month;

-- Category totals per user
CREATE VIEW IF NOT EXISTS vw_category_summary AS
SELECT
  e.user_id,
  COALESCE(c.name, 'Uncategorized') AS category,
  SUM(e.amount) AS total_amount,
  COUNT(*) AS tx_count
FROM expenses e
LEFT JOIN categories c ON e.category_id = c.id
GROUP BY e.user_id, category;

COMMIT;
