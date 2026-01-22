-- LinkedIn Sales Copilot Database Schema
-- Run this script to create the database and tables

CREATE DATABASE IF NOT EXISTS linkedin_sales_copilot;
USE linkedin_sales_copilot;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR(255) PRIMARY KEY,
    balance INT NOT NULL DEFAULT 200000,
    used INT NOT NULL DEFAULT 0,
    name VARCHAR(255),
    linkedin_profile_url VARCHAR(500),
    api_key VARCHAR(255) UNIQUE,
    api_key_created_at TIMESTAMP NULL,
    last_api_call_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_created_at (created_at),
    INDEX idx_linkedin_profile_url (linkedin_profile_url),
    INDEX idx_api_key (api_key),
    INDEX idx_last_api_call_at (last_api_call_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- API rate limiting table
CREATE TABLE IF NOT EXISTS api_rate_limits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    api_key VARCHAR(255) NOT NULL,
    endpoint VARCHAR(255) NOT NULL,
    request_count INT NOT NULL DEFAULT 1,
    window_start TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_api_key_endpoint (api_key, endpoint),
    INDEX idx_window_start (window_start)
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
-- Generated Content table (for storing AI-generated LinkedIn content)
CREATE TABLE IF NOT EXISTS generated_content (
    content_id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    content_type VARCHAR(50) NOT NULL,
    topic VARCHAR(500),
    tone VARCHAR(50),
    content TEXT NOT NULL,
    title VARCHAR(500),
    strategy TEXT,
    tips JSON,
    hashtags JSON,
    image_url VARCHAR(1000),
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_content_type (content_type),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

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

-- Content Analyses table (for storing content inspiration analyses)
CREATE TABLE IF NOT EXISTS content_analyses (
    analysis_id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    profile_url VARCHAR(500) NOT NULL,
    profile_name VARCHAR(255),
    analysis_type VARCHAR(50) DEFAULT 'content_inspiration',
    analysis_data JSON NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_profile_url (profile_url),
    INDEX idx_analysis_type (analysis_type),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Job Analyses table (for storing LinkedIn job posting analyses)
CREATE TABLE IF NOT EXISTS job_analyses (
    job_analysis_id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    job_url VARCHAR(500) NOT NULL,
    job_title VARCHAR(500),
    company_name VARCHAR(255),
    location VARCHAR(255),
    employment_type VARCHAR(100),
    seniority_level VARCHAR(100),
    job_function VARCHAR(255),
    industries JSON,
    description TEXT,
    requirements TEXT,
    responsibilities TEXT,
    skills_required JSON,
    qualifications JSON,
    benefits JSON,
    salary_range VARCHAR(255),
    posted_date VARCHAR(100),
    applicants_count VARCHAR(100),
    raw_data JSON,
    analyzed_data JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_job_url (job_url),
    INDEX idx_company_name (company_name),
    INDEX idx_job_title (job_title),
    INDEX idx_created_at (created_at),
    UNIQUE KEY unique_user_job (user_id, job_url)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Interview Question Sets table (for grouping questions for a job)
CREATE TABLE IF NOT EXISTS interview_question_sets (
    set_id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    job_analysis_id VARCHAR(255) NOT NULL,
    set_name VARCHAR(255),
    total_questions INT,
    categories_included JSON,
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (job_analysis_id) REFERENCES job_analyses(job_analysis_id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_job_analysis_id (job_analysis_id),
    INDEX idx_generated_at (generated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Interview Questions table (for storing individual questions)
CREATE TABLE IF NOT EXISTS interview_questions (
    question_id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    job_analysis_id VARCHAR(255) NOT NULL,
    set_id VARCHAR(255),
    question_text TEXT NOT NULL,
    question_category VARCHAR(100) NOT NULL,
    difficulty_level VARCHAR(50),
    suggested_answer TEXT,
    best_answer TEXT,
    tips TEXT,
    related_skills JSON,
    question_order INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (job_analysis_id) REFERENCES job_analyses(job_analysis_id) ON DELETE CASCADE,
    FOREIGN KEY (set_id) REFERENCES interview_question_sets(set_id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_job_analysis_id (job_analysis_id),
    INDEX idx_set_id (set_id),
    INDEX idx_category (question_category)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
