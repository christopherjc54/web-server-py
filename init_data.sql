-- add sample data

USE `DatabaseServer`;
INSERT INTO Account VALUES(
    "sampleuser",                                                           -- username
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",     -- password hash (password is "password")
    "8cc36E0a5A5b04A8",                                                     -- salt
    "43ea5f3e6d4b9f71bd478cf49e8f3c7df6b0fdd45d25637ef2fba73e8df431e4"      -- salted and hashed password
);