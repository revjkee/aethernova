-- /orchestrator/deployment_scripts/ansible/roles/webserver/tests/database/files/init_db.sql

-- Скрипт инициализации тестовой базы данных

DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS orders CASCADE;
DROP TABLE IF EXISTS products CASCADE;

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price NUMERIC(10, 2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    quantity INTEGER NOT NULL CHECK (quantity > 0),
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Вставка тестовых данных

INSERT INTO users (username, email) VALUES
('testuser1', 'testuser1@example.com'),
('testuser2', 'testuser2@example.com');

INSERT INTO products (name, description, price) VALUES
('Product A', 'Description for product A', 9.99),
('Product B', 'Description for product B', 19.99);

INSERT INTO orders (user_id, product_id, quantity) VALUES
(1, 1, 2),
(2, 2, 1);
