-- Incremental migrations — safe to run after init.sql
-- All statements use IF NOT EXISTS so they are no-ops on a fresh DB.

USE moneyflow_db;

CREATE TABLE IF NOT EXISTS avatar_upload_attempts (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    member_id   INT NOT NULL,
    uploaded_at DATETIME NOT NULL DEFAULT NOW(),
    INDEX idx_member_time (member_id, uploaded_at)
) ENGINE=InnoDB;

DROP EVENT IF EXISTS clean_avatar_upload_attempts;
CREATE EVENT clean_avatar_upload_attempts
ON SCHEDULE EVERY 10 MINUTE
DO
    DELETE FROM avatar_upload_attempts
    WHERE uploaded_at < DATE_SUB(NOW(), INTERVAL 1 HOUR);

CREATE TABLE IF NOT EXISTS registration_attempts (
    id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    created_at DATETIME    NOT NULL DEFAULT NOW(),
    INDEX idx_ip_time (ip_address, created_at)
) ENGINE=InnoDB;

DROP EVENT IF EXISTS clean_registration_attempts;
CREATE EVENT clean_registration_attempts
ON SCHEDULE EVERY 1 HOUR
DO
    DELETE FROM registration_attempts
    WHERE created_at < DATE_SUB(NOW(), INTERVAL 24 HOUR);

CREATE TABLE IF NOT EXISTS search_rate_limit (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address  VARCHAR(45) NOT NULL,
    searched_at DATETIME    NOT NULL DEFAULT NOW(),
    INDEX idx_ip_time (ip_address, searched_at)
) ENGINE=InnoDB;

-- Cleanup event (recreate only if missing)
DROP EVENT IF EXISTS clean_search_rate_limit;
CREATE EVENT clean_search_rate_limit
ON SCHEDULE EVERY 1 MINUTE
DO
    DELETE FROM search_rate_limit
    WHERE searched_at < DATE_SUB(NOW(), INTERVAL 5 MINUTE);
