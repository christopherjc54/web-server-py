-- configure database server for first time as root

CREATE USER "user" IDENTIFIED BY "1234";
GRANT ALL PRIVILEGES ON * . * TO "user";
FLUSH PRIVILEGES;