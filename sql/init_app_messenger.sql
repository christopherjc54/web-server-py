-- configure "Messenger" application database tables and procedures after logging in as "user"

USE `DatabaseServer`;

DROP TABLE IF EXISTS `Message`;
CREATE TABLE `Message` (                        -- doesn't have foreign keys on usernames because messages still exist after user is deleted
                                                -- should probably check for orphan messages when deleting a user (also prevents creating new account to view old messages)
    `id` INT NOT NULL AUTO_INCREMENT,
    `sentDateTime` DATETIME DEFAULT NOW(),
    `messageContent` VARCHAR(500),
    PRIMARY KEY (`id`),
    UNIQUE (`id`)
);

DROP TABLE IF EXISTS `SentItem`;
CREATE TABLE `SentItem` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `username` VARCHAR(15),
    `messageID` INT,
    PRIMARY KEY (`id`),
    UNIQUE (`id`)
);

DROP TABLE IF EXISTS `Inbox`;
CREATE TABLE `Inbox` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `fromUsername` VARCHAR(15),
    `toUsername` VARCHAR(15),
    `messageID` INT,
    `messageRead` BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (`id`),
    UNIQUE (`id`)
);

DROP TABLE IF EXISTS `File`;
CREATE TABLE `File` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `messageID` INT,
    `fileName` VARCHAR(50),
    `remoteFileID` VARCHAR(33),
    PRIMARY KEY (`id`),
    UNIQUE (`id`)
);

DROP PROCEDURE IF EXISTS `DeleteOrphanMessages`;
DELIMITER $$ ;
CREATE PROCEDURE `DeleteOrphanMessages` (
    IN sp_username VARCHAR(15)                  -- optimizes deletion...maybe
)
BEGIN
    -- DELETE m
    -- FROM Message m
    -- LEFT JOIN Account a ON m.fromUsername = a.username OR m.toUsername = a.username
    -- WHERE (m.fromUsername = sp_username OR m.toUsername = sp_username) AND a.username IS NULL;
END$$
DELIMITER ; $$