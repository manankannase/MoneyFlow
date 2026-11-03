-- Stop the old web service and take a verified backup before running this once.
-- DDL commits in MySQL. Restore the backup if migration fails; do not rerun blindly.
USE moneyflow_db;
DELIMITER //
CREATE PROCEDURE assert_v1_data()
BEGIN
 IF EXISTS(SELECT 1 FROM members WHERE account_balance IS NULL OR account_balance < 0 OR account_name NOT REGEXP '^[a-zA-Z0-9_]{3,30}$') THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Invalid legacy member data; resolve before migration';
 END IF;
END//
DELIMITER ;
CALL assert_v1_data();
DROP PROCEDURE assert_v1_data;
ALTER TABLE members MODIFY account_balance DECIMAL(12,2) NOT NULL DEFAULT 100.00;
-- All old sessions are revoked as part of the security upgrade.
DELETE FROM member_sessions;
ALTER TABLE member_sessions ADD last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE transfer_ledger DROP INDEX idx_unique_transfer,
 ADD idempotency_key CHAR(64) NULL,
 ADD request_hash CHAR(64) NULL;
UPDATE transfer_ledger SET idempotency_key=SHA2(CONCAT('legacy:',id),256), request_hash=SHA2(CONCAT('legacy:',id),256);
ALTER TABLE transfer_ledger MODIFY idempotency_key CHAR(64) NOT NULL,
 MODIFY request_hash CHAR(64) NOT NULL,
 ADD UNIQUE KEY sender_request (sender_id,idempotency_key);
-- Preserve the historical event log intact under its original format.
RENAME TABLE event_chronicle TO event_chronicle_v1;
CREATE TABLE event_chronicle (
 id BIGINT AUTO_INCREMENT PRIMARY KEY, member_id INT NULL,
 event_type VARCHAR(40) NOT NULL, ip_hash CHAR(64) NOT NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(member_id) REFERENCES members(id) ON DELETE RESTRICT,
 INDEX(created_at)
) ENGINE=InnoDB;
CREATE TABLE request_limits (
 bucket_key CHAR(64) NOT NULL, bucket BIGINT NOT NULL,
 attempts INT NOT NULL DEFAULT 0 CHECK(attempts>=0),
 PRIMARY KEY(bucket_key,bucket)
) ENGINE=InnoDB;
CREATE TABLE schema_version (version INT PRIMARY KEY);
INSERT INTO schema_version VALUES (2);
-- Apply deploy/grants.sql separately after creating moneyflow_app if needed.
