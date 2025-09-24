-- Инициализация базы данных TeslaAI: схема, таблицы и индексы

-- Создание схемы
CREATE SCHEMA IF NOT EXISTS tesla_ai AUTHORIZATION postgres;

-- Таблица пользователей
CREATE TABLE IF NOT EXISTS tesla_ai.users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    last_login TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    role VARCHAR(20) DEFAULT 'user'
);

-- Индекс для ускорения поиска по email
CREATE INDEX IF NOT EXISTS idx_users_email ON tesla_ai.users(email);

-- Таблица логов аутентификации
CREATE TABLE IF NOT EXISTS tesla_ai.auth_logs (
    log_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES tesla_ai.users(user_id) ON DELETE CASCADE,
    login_time TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    success BOOLEAN NOT NULL,
    ip_address INET,
    user_agent TEXT
);

-- Таблица событий безопасности
CREATE TABLE IF NOT EXISTS tesla_ai.security_events (
    event_id SERIAL PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    event_timestamp TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    user_id INT REFERENCES tesla_ai.users(user_id),
    description TEXT
);

-- Таблица сессий пользователей
CREATE TABLE IF NOT EXISTS tesla_ai.sessions (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id INT REFERENCES tesla_ai.users(user_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    ip_address INET
);

-- Индекс для быстрого поиска активных сессий
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON tesla_ai.sessions(user_id);

-- Создание расширения для генерации UUID (если еще не установлено)
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Триггер для обновления last_login при успешном входе
CREATE OR REPLACE FUNCTION update_last_login() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.success THEN
        UPDATE tesla_ai.users SET last_login = NEW.login_time WHERE user_id = NEW.user_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_update_last_login ON tesla_ai.auth_logs;
CREATE TRIGGER trg_update_last_login AFTER INSERT ON tesla_ai.auth_logs
FOR EACH ROW EXECUTE FUNCTION update_last_login();

