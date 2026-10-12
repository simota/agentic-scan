-- Larder schema
CREATE TABLE items (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  price_cents INTEGER NOT NULL,
  household TEXT,
  legacy_sku TEXT
);
CREATE INDEX idx_items_legacy_sku ON items (legacy_sku);

CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  email TEXT NOT NULL,
  fax_number TEXT
);

CREATE TABLE payments (
  stripe_id TEXT PRIMARY KEY,
  amount INTEGER NOT NULL
);

CREATE TABLE experiment_assignments (
  visitor TEXT,
  bucket TEXT
);

CREATE TABLE old_audit_log (
  id INTEGER PRIMARY KEY,
  message TEXT
);
