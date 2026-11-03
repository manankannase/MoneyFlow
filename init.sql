USE moneyflow_db;
CREATE TABLE schema_version (version INT PRIMARY KEY);
INSERT INTO schema_version VALUES (2);
CREATE TABLE members (
 id INT AUTO_INCREMENT PRIMARY KEY,
 account_name VARCHAR(30) NOT NULL UNIQUE,
 email_address VARCHAR(255) NOT NULL UNIQUE,
 password_hash VARCHAR(255) NOT NULL,
 account_balance DECIMAL(12,2) NOT NULL DEFAULT 100.00 CHECK (account_balance >= 0),
 member_bio TEXT, profile_photo VARCHAR(255),
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;
CREATE TABLE member_sessions (
 id INT AUTO_INCREMENT PRIMARY KEY, member_id INT NOT NULL,
 token_hash CHAR(64) NOT NULL UNIQUE, csrf_token CHAR(64) NOT NULL,
 agent_hash CHAR(64) NOT NULL, ip_address VARCHAR(45) NOT NULL,
 expires_at DATETIME NOT NULL, last_seen DATETIME NOT NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY (member_id) REFERENCES members(id) ON DELETE CASCADE,
 INDEX (expires_at), INDEX (member_id)
) ENGINE=InnoDB;
CREATE TABLE transfer_ledger (
 id BIGINT AUTO_INCREMENT PRIMARY KEY,
 sender_id INT NOT NULL, recipient_id INT NOT NULL,
 transfer_amount DECIMAL(10,2) NOT NULL CHECK (transfer_amount > 0),
 memo_text VARCHAR(500) NOT NULL DEFAULT '',
 idempotency_key CHAR(64) NOT NULL,
 request_hash CHAR(64) NOT NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE (sender_id, idempotency_key),
 CHECK (sender_id <> recipient_id),
 FOREIGN KEY (sender_id) REFERENCES members(id) ON DELETE RESTRICT,
 FOREIGN KEY (recipient_id) REFERENCES members(id) ON DELETE RESTRICT,
 INDEX (sender_id, id), INDEX (recipient_id, id)
) ENGINE=InnoDB;
CREATE TABLE event_chronicle (
 id BIGINT AUTO_INCREMENT PRIMARY KEY,
 member_id INT NULL, event_type VARCHAR(40) NOT NULL, ip_hash CHAR(64) NOT NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY (member_id) REFERENCES members(id) ON DELETE RESTRICT,
 INDEX (created_at)
) ENGINE=InnoDB;
CREATE TABLE request_limits (
 bucket_key CHAR(64) NOT NULL, bucket BIGINT NOT NULL,
 attempts INT NOT NULL DEFAULT 0 CHECK (attempts >= 0),
 PRIMARY KEY (bucket_key, bucket)
) ENGINE=InnoDB;
