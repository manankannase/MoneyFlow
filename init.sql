-- MoneyFlow Database Initialization

-- Create database
CREATE DATABASE IF NOT EXISTS moneyflow_db 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

USE moneyflow_db;

-- Members table (stores user accounts)
CREATE TABLE members (
    id INT AUTO_INCREMENT PRIMARY KEY,
    account_name VARCHAR(255) UNIQUE NOT NULL,
    email_address VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    account_balance DECIMAL(12, 2) DEFAULT 100.00 CHECK (account_balance >= 0),
    member_bio TEXT,
    profile_photo VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_account_name (account_name),
    INDEX idx_email_address (email_address)
);

-- Sessions table (custom session management)
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
);

-- Transfer ledger table (tracks all money transfers)
CREATE TABLE transfer_ledger (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    recipient_id INT NOT NULL,
    transfer_amount DECIMAL(10, 2) NOT NULL,
    memo_text TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES members(id) ON DELETE RESTRICT,
    FOREIGN KEY (recipient_id) REFERENCES members(id) ON DELETE RESTRICT,
    INDEX idx_sender_id (sender_id),
    INDEX idx_recipient_id (recipient_id),
    INDEX idx_created_at (created_at)
);

-- Event chronicle table (activity logging)
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
);

-- Failed authentication attempts (rate limiting)
CREATE TABLE failed_auth_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address   VARCHAR(45)  NOT NULL,
    -- FIX V7: track per (ip, account_name) so successful login on one account
    -- cannot reset the counter for a different account under attack
    account_name VARCHAR(50)  NOT NULL DEFAULT '',
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip_account (ip_address, account_name),
    INDEX idx_created_at (created_at)
);

-- Auto-clean old failed attempts (older than 1 day)
CREATE EVENT clean_old_failures
ON SCHEDULE EVERY 1 HOUR
DO
    DELETE FROM failed_auth_attempts 
    WHERE created_at < DATE_SUB(NOW(), INTERVAL 1 DAY);

-- Pending transfers: DB intent binding for tamper-proof transfers
CREATE TABLE IF NOT EXISTS pending_transfers (
    id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    transaction_id CHAR(64) NOT NULL UNIQUE,
    sender_id      INT NOT NULL,
    recipient_id   INT NOT NULL,
    amount         DECIMAL(15,2) NOT NULL,
    nonce          CHAR(32) NOT NULL,
    created_at     DATETIME NOT NULL DEFAULT NOW(),
    expires_at     DATETIME NOT NULL,
    used           TINYINT(1) NOT NULL DEFAULT 0,
    INDEX idx_txn (transaction_id),
    INDEX idx_cleanup (expires_at, used)
) ENGINE=InnoDB;

-- Avatar upload rate limit table (per-member throttling — max 10 uploads per hour)
CREATE TABLE IF NOT EXISTS avatar_upload_attempts (
    id        INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    member_id INT NOT NULL,
    uploaded_at DATETIME NOT NULL DEFAULT NOW(),
    INDEX idx_member_time (member_id, uploaded_at)
) ENGINE=InnoDB;

-- Auto-clean old avatar upload records (older than 1 hour)
CREATE EVENT clean_avatar_upload_attempts
ON SCHEDULE EVERY 10 MINUTE
DO
    DELETE FROM avatar_upload_attempts
    WHERE uploaded_at < DATE_SUB(NOW(), INTERVAL 1 HOUR);

-- Registration attempts table (per-IP throttling — max 5 accounts per IP per 24 hours)
CREATE TABLE IF NOT EXISTS registration_attempts (
    id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    created_at DATETIME    NOT NULL DEFAULT NOW(),
    INDEX idx_ip_time (ip_address, created_at)
) ENGINE=InnoDB;

-- Auto-clean old registration attempt records (older than 24 hours)
CREATE EVENT clean_registration_attempts
ON SCHEDULE EVERY 1 HOUR
DO
    DELETE FROM registration_attempts
    WHERE created_at < DATE_SUB(NOW(), INTERVAL 24 HOUR);

-- Search rate limit table (per-IP throttling)
CREATE TABLE IF NOT EXISTS search_rate_limit (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    searched_at DATETIME NOT NULL DEFAULT NOW(),
    INDEX idx_ip_time (ip_address, searched_at)
) ENGINE=InnoDB;

-- Auto-clean expired sessions (older than 1 day)
CREATE EVENT clean_expired_sessions
ON SCHEDULE EVERY 1 HOUR
DO
    DELETE FROM member_sessions
    WHERE expires_at < NOW();

-- Auto-clean expired/used pending transfers (older than 1 hour)
CREATE EVENT clean_expired_pending_transfers
ON SCHEDULE EVERY 10 MINUTE
DO
    DELETE FROM pending_transfers
    WHERE (expires_at < NOW() AND used = 0) OR (used = 1 AND created_at < DATE_SUB(NOW(), INTERVAL 1 HOUR));

-- Auto-clean old search rate limit entries (older than 5 minutes)
CREATE EVENT clean_search_rate_limit
ON SCHEDULE EVERY 1 MINUTE
DO
    DELETE FROM search_rate_limit
    WHERE searched_at < DATE_SUB(NOW(), INTERVAL 5 MINUTE);

-- Restrict DB user privileges: remove dangerous ones, keep only needed ones.
-- The Docker entrypoint grants ALL on moneyflow_db, so we revoke and re-grant.
-- We must revoke the grant given by Docker (which is ALL PRIVILEGES on moneyflow_db).
REVOKE ALL PRIVILEGES, GRANT OPTION ON moneyflow_db.* FROM 'moneyflow_admin'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON moneyflow_db.* TO 'moneyflow_admin'@'%';
FLUSH PRIVILEGES;
