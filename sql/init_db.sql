-- configure database for first time or reset it after logging in as "user"

DROP DATABASE IF EXISTS `DatabaseServer`;       -- use either "drop database" or most "drop table"/"drop procedure"s
CREATE DATABASE `DatabaseServer`;
USE `DatabaseServer`;

DROP TABLE IF EXISTS `Account`;
CREATE TABLE `Account` (
    `id` INT NOT NULL AUTO_INCREMENT,           -- might not be in program, still good for sorting accounts by creation order
                                                -- id everywhere else is good practice
    `username` VARCHAR(15),
    `displayName` VARCHAR(32),
    `salt` VARCHAR(16),                         -- 4 bytes * 2^4 bits for hex digits => 64 bits minimum entropy
                                                -- 16 hex chars * 2^4 bits = 256 bits > 64 bits
    `hash` VARCHAR(128),                        -- SHA3-512 hex digest
                                                -- SHA3-256/SHA3-512 not susceptible to collision attacks (like MD5 is) or length extension attacks (like SHA-256 is)
                                                -- SHA3-512 only takes about twice as long as SHA-256 or SHA3-256 => O(2n) => linear time
                                                -- 512 bit output / 4 bits per hex digit = 128 hex digits
    PRIMARY KEY (`username`),
    UNIQUE (`id`, `username`, `displayName`)
);

DROP TABLE IF EXISTS `Session`;
CREATE TABLE `Session` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `username` VARCHAR(15),
    `sessionID` VARCHAR(32),                    -- lower-case hex token
                                                -- 8 bytes * 2^4 bits for hex digits => 128 bits minimum entropy
                                                -- 32 hex chars * 2^4 bits = 512 bits > 128 bits
    `expDateTime` DATETIME,
    PRIMARY KEY (`id`),
    FOREIGN KEY (`username`) REFERENCES Account(`username`),
    UNIQUE (`id`)
);