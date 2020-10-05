-- configure "Messenger" application database tables and procedures

USE `DatabaseServer`;

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