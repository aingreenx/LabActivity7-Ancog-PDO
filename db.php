<?php
declare(strict_types=1);

/*
 * DATABASE SETUP (run once in MySQL / phpMyAdmin):
 *
 * CREATE DATABASE IF NOT EXISTS blog_site CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
 * USE blog_site;
 *
 * CREATE TABLE users (
 *     id INT UNSIGNED NOT NULL AUTO_INCREMENT,
 *     name VARCHAR(50) NOT NULL,
 *     email VARCHAR(255) NOT NULL,
 *     password_hash VARCHAR(255) NOT NULL,
 *     created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 *     PRIMARY KEY (id),
 *     UNIQUE KEY uq_users_email (email)
 * ) ENGINE=InnoDB;
 *
 * CREATE TABLE posts (
 *     id INT UNSIGNED NOT NULL AUTO_INCREMENT,
 *     user_id INT UNSIGNED NOT NULL,
 *     title VARCHAR(150) NOT NULL,
 *     content TEXT NOT NULL,
 *     created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 *     updated_at TIMESTAMP NULL DEFAULT NULL,
 *     PRIMARY KEY (id),
 *     KEY idx_posts_user_id (user_id),
 *     KEY idx_posts_created_at (created_at),
 *     CONSTRAINT fk_posts_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
 * ) ENGINE=InnoDB;
 *
 * CREATE TABLE comments (
 *     id INT UNSIGNED NOT NULL AUTO_INCREMENT,
 *     post_id INT UNSIGNED NOT NULL,
 *     user_id INT UNSIGNED NOT NULL,
 *     content TEXT NOT NULL,
 *     created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 *     updated_at TIMESTAMP NULL DEFAULT NULL,
 *     PRIMARY KEY (id),
 *     KEY idx_comments_post_id (post_id),
 *     KEY idx_comments_user_id (user_id),
 *     CONSTRAINT fk_comments_post FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE,
 *     CONSTRAINT fk_comments_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
 * ) ENGINE=InnoDB;
 */


const DB_HOST = '127.0.0.1';
const DB_PORT = '3306';
const DB_NAME = 'blog_site';
const DB_USER = 'root';
const DB_PASS = '';

const APP_NAME = 'Blog Site';
const MAX_LOGIN_ATTEMPTS = 5;

$pdo = new PDO(
    sprintf('mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4',
        getenv('DB_HOST') ?: DB_HOST, getenv('DB_PORT') ?: DB_PORT, getenv('DB_NAME') ?: DB_NAME),
    getenv('DB_USER') ?: DB_USER,
    getenv('DB_PASS') !== false ? (string) getenv('DB_PASS') : DB_PASS,
    [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ]
);

// Secure session cookie flags, then start the session (before any HTML output).
$isHttps = ($_SERVER['HTTPS'] ?? '') !== '' && ($_SERVER['HTTPS'] ?? '') !== 'off';
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'secure'   => $isHttps,
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();

/** Escape any value for safe HTML output. */
function e(?string $value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** CSRF helpers: every POST form carries this token. */
function csrf_token(): string
{
    return $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
}

function csrf_valid(mixed $token): bool
{
    return is_string($token) && hash_equals(csrf_token(), $token);
}
