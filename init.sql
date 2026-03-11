-- =============================================================
-- MoneyFlow Database Initialization — Hardened Schema
-- =============================================================

-- Enable event scheduler for automated cleanup tasks
SET GLOBAL event_scheduler = ON;

-- Create database
CREATE DATABASE IF NOT EXISTS moneyflow_db
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE moneyflow_db;

-- =============================================================
-- Members table (stores user accounts)
-- =============================================================
CREATE TABLE members (
    id INT AUTO_INCREMENT PRIMARY KEY,
    account_name VARCHAR(255) UNIQUE NOT NULL,
    email_address VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    account_balance DECIMAL(12, 2) DEFAULT 100.00,
    member_bio TEXT,
    profile_photo VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    -- Prevent negative balances at the database level
    CONSTRAINT chk_balance_non_negative CHECK (account_balance >= 0),
    INDEX idx_account_name (account_name),
    INDEX idx_email_address (email_address)
) ENGINE=InnoDB;

-- =============================================================
-- Sessions table (custom session management)
-- =============================================================
CREATE TABLE member_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    member_id INT NOT NULL,
    token_hash VARCHAR(64) UNIQUE NOT NULL,
    csrf_token VARCHAR(64) NOT NULL,
    agent_hash VARCHAR(64) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (member_id) REFERENCES members(id) ON DELETE CASCADE,
    INDEX idx_member_id (member_id),
    INDEX idx_token_hash (token_hash),
    INDEX idx_expires_at (expires_at)
) ENGINE=InnoDB;

-- =============================================================
-- Transfer ledger table (tracks all money transfers)
-- SECURITY: ON DELETE RESTRICT — financial records must NEVER
-- be silently deleted when a member account is removed.
-- =============================================================
CREATE TABLE transfer_ledger (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    recipient_id INT NOT NULL,
    transfer_amount DECIMAL(10, 2) NOT NULL,
    memo_text TEXT NOT NULL DEFAULT (''),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- Prevent zero or negative transfer amounts
    CONSTRAINT chk_transfer_amount_positive CHECK (transfer_amount > 0),
    -- Prevent self-transfers at DB level
    CONSTRAINT chk_no_self_transfer CHECK (sender_id <> recipient_id),
    -- Prevent exact duplicate transactions (same sender, recipient, amount, time)
    UNIQUE INDEX idx_unique_transfer (sender_id, recipient_id, transfer_amount, created_at),
    FOREIGN KEY (sender_id) REFERENCES members(id) ON DELETE RESTRICT,
    FOREIGN KEY (recipient_id) REFERENCES members(id) ON DELETE RESTRICT,
    INDEX idx_sender_id (sender_id),
    INDEX idx_recipient_id (recipient_id),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB;

-- =============================================================
-- Event chronicle table (activity logging)
-- =============================================================
CREATE TABLE event_chronicle (
    id INT AUTO_INCREMENT PRIMARY KEY,
    member_id INT,
    account_name VARCHAR(255),
    page_path VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    access_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (member_id) REFERENCES members(id) ON DELETE SET NULL,
    INDEX idx_member_id (member_id),
    INDEX idx_access_timestamp (access_timestamp)
) ENGINE=InnoDB;

-- =============================================================
-- Failed authentication attempts (rate limiting)
-- =============================================================
CREATE TABLE failed_auth_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    account_name VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip_address (ip_address),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB;

-- =============================================================
-- Automated Cleanup Events
-- =============================================================

-- Auto-clean old failed attempts (older than 1 day)
CREATE EVENT IF NOT EXISTS clean_old_failures
ON SCHEDULE EVERY 1 HOUR
DO
    DELETE FROM failed_auth_attempts
    WHERE created_at < DATE_SUB(NOW(), INTERVAL 1 DAY);

-- Auto-clean expired sessions (older than 1 day)
CREATE EVENT IF NOT EXISTS clean_expired_sessions
ON SCHEDULE EVERY 1 HOUR
DO
    DELETE FROM member_sessions
    WHERE expires_at < NOW();