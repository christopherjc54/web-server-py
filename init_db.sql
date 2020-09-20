-- configure db for first time after logging in as 'user'

DROP DATABASE IF EXISTS `DatabaseServer`;
CREATE DATABASE `DatabaseServer`;
USE `DatabaseServer`;
DROP TABLE IF EXISTS `Account`;
CREATE TABLE `Account` (
    `username` VARCHAR(15),
    `passwordHash` VARCHAR(256),    -- do not use in production
    `salt` VARCHAR(16),             -- 16 hex digits => 64 bits
    `hash` VARCHAR(256),            -- SHA-256
    PRIMARY KEY (`username`)
);