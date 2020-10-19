-- configure "Messenger" application database after logging in as "user"

USE `DatabaseServer`;

DROP TABLE IF EXISTS `Message`;
CREATE TABLE `Message` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `sentDateTime` DATETIME DEFAULT NOW(),
    `messageContent` VARCHAR(500),
    PRIMARY KEY (`id`),
    UNIQUE (`id`)
);

DROP TABLE IF EXISTS `Sent`;
CREATE TABLE `Sent` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `fromUsername` VARCHAR(15),
    `toUsername` VARCHAR(15),
    `messageID` INT,
    PRIMARY KEY (`id`),
    FOREIGN KEY (`messageID`) REFERENCES Message(`id`),
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
    FOREIGN KEY (`messageID`) REFERENCES Message(`id`),
    UNIQUE (`id`)
);

DROP TABLE IF EXISTS `File`;
CREATE TABLE `File` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `messageID` INT,
    `fileName` VARCHAR(50),
    `remoteFileID` VARCHAR(33),
    PRIMARY KEY (`id`),
    FOREIGN KEY (`messageID`) REFERENCES Message(`id`),
    UNIQUE (`id`)
);