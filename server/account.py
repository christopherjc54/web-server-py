#!/usr/bin/env python3

import mysql.connector
import random, string
import hashlib
import logging

from __main__ import Global

class Account:

    def add(username, original_password, display_name, plain_text=True):
        Global.cursor.execute(
            "SELECT * FROM Account WHERE username = %s",
            (username,)
        )
        result = Global.cursor.fetchall()
        if len(result) > 0:
            error_message = "user \"" + username + "\" already exists"
            logging.error(error_message)
            return False, error_message
        salt = ''.join(random.SystemRandom().choice(string.hexdigits) for _ in range(16))
        if plain_text:
            hashed_password = hashlib.sha256(original_password.encode(Global.encoding)).hexdigest()
        else:
            hashed_password = original_password
        hash = hashlib.sha256(hashed_password.encode(Global.encoding) + salt.encode(Global.encoding)).hexdigest()
        try:
            Global.cursor.execute(
                "INSERT INTO Account (username, displayName, salt, hash) VALUES (%s, %s, %s, %s);",
                (username, display_name, salt, hash)
            )
            Global.db.commit() ## would need exception check and db.rollback() if one of many commits fail (ACID property)
        except mysql.connector.DataError as e:
            assert "data too long" in e.msg.lower()
            error_message = "username must be 15 or less characters"
            logging.error(error_message)
            return False, error_message

        print()
        logging.debug("Added new account to database:")
        logging.debug("  Username: " + username)
        if plain_text:
            logging.debug("  Password: " + original_password)
        logging.debug("  Hashed Password: " + hashed_password)
        logging.debug("  Salt: " + salt)
        logging.debug("  Hash: " + hash)
        print()

        return True, ""

    def remove(username):
        try:
            Global.cursor.execute(
                "DELETE FROM Session WHERE username = %s;",
                (username,)
            )
            Global.cursor.execute(
                "DELETE FROM Account WHERE username = %s;",
                (username,)
            )
            Global.db.commit()
            return True
        except mysql.connector.Error as e:
            logging.critical(e.msg)
            Global.db.rollback()
        return False

    def validate(username, password_hash):
        Global.cursor.execute(
            "SELECT username, salt, hash FROM Account WHERE username = %s;",
            (username,)
        )
        result = Global.cursor.fetchall()
        if len(result) > 0:
            for db_username, db_salt, db_hash in result:
                salted_hash = hashlib.sha256(password_hash.encode(Global.encoding) + db_salt.encode(Global.encoding)).hexdigest()
                if db_username == username and db_hash == salted_hash:
                    return True
            logging.error("\"" + username + "\" tried logging in with wrong password")
        else:
            logging.error("user \"" + username + "\" not found")
        return False

    def get_all_as_string():
        Global.cursor.execute("SELECT username, displayName, salt, hash FROM Account;")
        result = Global.cursor.fetchall()
        if len(result) > 0:
            account_str = ""
            for index, (db_username, db_display_name, db_salt, db_hash) in enumerate(result):
                account_str += "Username: " + db_username
                account_str += "\n" + "Display Name: " + db_display_name
                # account_str += "\n" + "Salt: " + db_salt
                # account_str += "\n" + "Hash: " + db_hash
                if index < len(result) - 1:
                    account_str += "\n\n"
            return account_str
        else:
            return "no accounts found"