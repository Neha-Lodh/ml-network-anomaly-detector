-- =========================================================
-- schema.sql
-- ML-Based Network Anomaly Detector - Database Schema (MySQL)
-- =========================================================
-- Run this once to create the database and tables.
-- In MySQL command line:
--     SOURCE schema.sql;
-- or:
--     mysql -u root -p < schema.sql
-- =========================================================

CREATE DATABASE IF NOT EXISTS network_anomaly_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE network_anomaly_db;

-- ---------------------------------------------------------
-- Table: traffic_records
-- Stores every network traffic row that has been analyzed,
-- along with the ML prediction results.
-- ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS traffic_records (
    id                  BIGINT AUTO_INCREMENT PRIMARY KEY,
    upload_batch_id     VARCHAR(64)     NOT NULL,
    record_timestamp    VARCHAR(64)     NULL,
    src_ip              VARCHAR(45)     NOT NULL,
    dst_ip              VARCHAR(45)     NOT NULL,
    src_port            INT             NOT NULL,
    dst_port            INT             NOT NULL,
    protocol            VARCHAR(10)     NOT NULL,
    duration            FLOAT           NOT NULL,
    packet_count        INT             NOT NULL,
    bytes_transferred   BIGINT          NOT NULL,
    failed_connections  INT             NOT NULL DEFAULT 0,
    is_anomaly          TINYINT(1)      NOT NULL DEFAULT 0,
    risk_score          INT             NOT NULL DEFAULT 0,
    risk_level          VARCHAR(10)     NOT NULL DEFAULT 'Low',
    created_at          TIMESTAMP       DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_batch (upload_batch_id),
    INDEX idx_created_at (created_at),
    INDEX idx_risk_level (risk_level)
) ENGINE=InnoDB;

-- ---------------------------------------------------------
-- Table: alerts
-- Stores one row per DETECTED ANOMALY (a subset of traffic_records)
-- with a human-readable explanation, for the Alerts page.
-- ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id                  BIGINT AUTO_INCREMENT PRIMARY KEY,
    traffic_record_id   BIGINT          NOT NULL,
    upload_batch_id     VARCHAR(64)     NOT NULL,
    src_ip              VARCHAR(45)     NOT NULL,
    dst_ip              VARCHAR(45)     NOT NULL,
    dst_port            INT             NOT NULL,
    protocol            VARCHAR(10)     NOT NULL,
    risk_score          INT             NOT NULL,
    risk_level          VARCHAR(10)     NOT NULL,
    explanation         VARCHAR(500)    NOT NULL,
    status              VARCHAR(20)     NOT NULL DEFAULT 'New',
    created_at          TIMESTAMP       DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_alert_traffic
        FOREIGN KEY (traffic_record_id) REFERENCES traffic_records(id)
        ON DELETE CASCADE,
    INDEX idx_alert_batch (upload_batch_id),
    INDEX idx_alert_risk (risk_level)
) ENGINE=InnoDB;
