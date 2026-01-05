-- LinkedIn Sales Copilot Database Schema
-- Run this script to create the database and tables

CREATE DATABASE IF NOT EXISTS linkedin_sales_copilot;
USE linkedin_sales_copilot;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR(255) PRIMARY KEY,
    balance INT NOT NULL DEFAULT 10000,
    used INT NOT NULL DEFAULT 0,
    name VARCHAR(255),
    linkedin_profile_url VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_created_at (created_at),
    INDEX idx_linkedin_profile_url (linkedin_profile_url)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Prospects table (for tracking analyzed prospects)
CREATE TABLE IF NOT EXISTS prospects (
    prospect_id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    linkedin_profile_url VARCHAR(500) NOT NULL,
    name VARCHAR(255),
    headline VARCHAR(500),
    company VARCHAR(255),
    location VARCHAR(255),
    analysis_status VARCHAR(50) DEFAULT 'pending',
    analyzed_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_linkedin_profile_url (linkedin_profile_url),
    INDEX idx_analysis_status (analysis_status),
    INDEX idx_created_at (created_at),
    UNIQUE KEY unique_user_prospect (user_id, linkedin_profile_url)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Transactions table (for credit usage)
CREATE TABLE IF NOT EXISTS transactions (
    transaction_id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    prospect_id VARCHAR(255),
    process_type VARCHAR(100) NOT NULL,
    process_description VARCHAR(500),
    tokens_used INT NOT NULL,
    input_tokens INT NOT NULL,
    output_tokens INT NOT NULL,
    cost DECIMAL(10, 6) NOT NULL,
    model VARCHAR(100),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (prospect_id) REFERENCES prospects(prospect_id) ON DELETE SET NULL,
    INDEX idx_user_id (user_id),
    INDEX idx_prospect_id (prospect_id),
    INDEX idx_process_type (process_type),
    INDEX idx_timestamp (timestamp),
    INDEX idx_model (model)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Payment transactions table (for Stripe payments)
CREATE TABLE IF NOT EXISTS payment_transactions (
    payment_id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    stripe_session_id VARCHAR(255) NOT NULL,
    stripe_payment_intent_id VARCHAR(255),
    package_id INT NOT NULL,
    package_name VARCHAR(100) NOT NULL,
    tokens_purchased INT NOT NULL,
    amount_paid DECIMAL(10, 2) NOT NULL,
    currency VARCHAR(10) NOT NULL DEFAULT 'usd',
    payment_status VARCHAR(50) NOT NULL,
    payment_method VARCHAR(50),
    customer_email VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_stripe_session_id (stripe_session_id),
    INDEX idx_payment_status (payment_status),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Analyses table (for storing complete analysis results)
CREATE TABLE IF NOT EXISTS analyses (
    analysis_id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    prospect_id VARCHAR(255),
    -- Seller configuration
    seller_goal TEXT,
    seller_offer TEXT,
    seller_icp TEXT,
    seller_proof TEXT,
    seller_risk_level VARCHAR(50),
    seller_offer_type VARCHAR(50),
    -- Analysis results (stored as JSON)
    analysis_data JSON NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (prospect_id) REFERENCES prospects(prospect_id) ON DELETE SET NULL,
    INDEX idx_user_id (user_id),
    INDEX idx_prospect_id (prospect_id),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

