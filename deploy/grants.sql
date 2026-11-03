-- Run as database administrator after schema initialization or migration.
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'moneyflow_app'@'%';
GRANT SELECT ON moneyflow_db.schema_version TO 'moneyflow_app'@'%';
GRANT SELECT, INSERT ON moneyflow_db.members TO 'moneyflow_app'@'%';
GRANT UPDATE (password_hash, account_balance, email_address, member_bio, profile_photo) ON moneyflow_db.members TO 'moneyflow_app'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON moneyflow_db.member_sessions TO 'moneyflow_app'@'%';
GRANT SELECT, INSERT ON moneyflow_db.transfer_ledger TO 'moneyflow_app'@'%';
GRANT INSERT ON moneyflow_db.event_chronicle TO 'moneyflow_app'@'%';
GRANT SELECT, INSERT, UPDATE ON moneyflow_db.request_limits TO 'moneyflow_app'@'%';
