-- configure db for first time after logging in as "user"

DROP DATABASE IF EXISTS `DatabaseServer`;   -- use either "drop database" or most "drop tables"
CREATE DATABASE `DatabaseServer`;
USE `DatabaseServer`;

DROP TABLE IF EXISTS `Account`;
CREATE TABLE `Account` (
    `id` INT NOT NULL AUTO_INCREMENT,       -- might not be used
    `username` VARCHAR(15),
    `displayName` VARCHAR(32),
    `salt` VARCHAR(16),                     -- 16 char * 4 bits for hex digits => 64 bits
    `hash` VARCHAR(256),                    -- SHA-256
    PRIMARY KEY (`username`),
    UNIQUE (`id`, `username`, `displayName`)
);

DROP TABLE IF EXISTS `Session`;
CREATE TABLE `Session` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `username` VARCHAR(15),
    `sessionID` VARCHAR(32),                -- 32 char * 4 bits for hex digits => 128 bits
    `expDateTime` DATETIME,
    PRIMARY KEY (`id`),
    FOREIGN KEY (`username`) REFERENCES Account(`username`),
    UNIQUE (`id`)
);

DROP TABLE IF EXISTS `Message`;
CREATE TABLE `Message` (                    -- doesn't have foreign keys on usernames because messages still exist after user is deleted
                                            -- should probably check for orphan messages when deleting a user (also prevents creating new account to view old messages)
    `id` INT NOT NULL AUTO_INCREMENT,
    `fromUsername` VARCHAR(15),
    `toUsername` VARCHAR(15),
    `message` VARCHAR(512),
    `sentDateTime` DATETIME,
    PRIMARY KEY (`id`),
    UNIQUE (`id`)
);

DROP PROCEDURE IF EXISTS `DeleteOrphanMessages`;
DELIMITER $$ ;
CREATE PROCEDURE `DeleteOrphanMessages`(
    IN sp_username VARCHAR(15)             -- optimizes deletion...maybe
)
BEGIN
    DELETE m
    FROM Message m
    LEFT JOIN Account a ON m.fromUsername = a.username OR m.toUsername = a.username
    WHERE (m.fromUsername = sp_username OR m.toUsername = sp_username) AND a.username IS NULL;
END$$
DELIMITER ; $$