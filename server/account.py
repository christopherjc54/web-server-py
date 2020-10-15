#!/usr/bin/env python3

import secrets
import hashlib
import logging

import mysql.connector
import argon2
from argon2._password_hasher import (
    DEFAULT_HASH_LENGTH,
    DEFAULT_MEMORY_COST,
    DEFAULT_PARALLELISM,
    DEFAULT_TIME_COST,
    Type
)

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
        salt = secrets.token_hex(int(16/2)) ## each byte gets converted to two hex digits
        sha_function = Global.config.get("miscellaneous", "sha_function")
        if sha_function.upper().startswith("SHA3"):
            hash_function = getattr(hashlib, sha_function.lower().replace("-", "_"))
        else:
            hash_function = getattr(hashlib, sha_function.lower().replace("-", ""))
        if plain_text:
            hashed_password = hash_function(original_password.encode(Global.encoding)).hexdigest()
        else:
            hashed_password = original_password
        salt_method = Global.config.get("miscellaneous", "salt_method")
        try:
            if salt_method.upper().startswith("SHA"):
                hash = hash_function(hashed_password.encode(Global.encoding) + salt.encode(Global.encoding)).hexdigest()
                Global.cursor.execute(
                    "INSERT INTO Account (username, displayName, salt, hash) VALUES (%s, %s, %s, %s);",
                    (username, display_name, salt, hash)
                )
            elif salt_method.lower() == "argon2":
                ## https://argon2-cffi.readthedocs.io/en/stable/argon2.html
                ## don't change type because Type.ID is the most secure, other parameters may be changed without resetting/migrating the database
                hash = argon2.hash_password(
                    password=hashed_password.encode(Global.encoding),
                    salt=salt.encode(Global.encoding),
                    time_cost=DEFAULT_TIME_COST,
                    memory_cost=DEFAULT_MEMORY_COST,
                    parallelism=DEFAULT_PARALLELISM,
                    hash_len=DEFAULT_HASH_LENGTH,
                    type=Type.ID,
                ).decode(Global.encoding)
                Global.cursor.execute(
                    "INSERT INTO Account (username, displayName, hash) VALUES (%s, %s, %s);",
                    (username, display_name, hash)
                )
            else:
                logging.critical("Salt method is invalid.")
                raise Exception
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
        if salt_method.lower() != "argon2":
            logging.debug("  Salt: " + salt)
        else:
            logging.debug("  Embedded Salt: " + salt)
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
            raise Exception

    def validate(username, password_hash):
        Global.cursor.execute(
            "SELECT username, salt, hash FROM Account WHERE username = %s;",
            (username,)
        )
        result = Global.cursor.fetchall()
        if len(result) > 0:
            salt_method_auto_read = Global.config.getboolean("miscellaneous", "salt_method_auto_read")
            salt_method = None
            if not salt_method_auto_read:
                salt_method = Global.config.get("miscellaneous", "salt_method")
            for db_username, db_salt, db_hash in result:
                if db_username == username:
                    sha_function = Global.config.get("miscellaneous", "sha_function")
                    if salt_method_auto_read:
                        salt_method = ("argon2" if db_hash.startswith("$argon2") else sha_function)
                    if salt_method.upper().startswith("SHA"):
                        if sha_function.upper().startswith("SHA3"):
                            hash_function = getattr(hashlib, sha_function.lower().replace("-", "_"))
                        else:
                            hash_function = getattr(hashlib, sha_function.lower().replace("-", ""))
                        if db_hash == hash_function(password_hash.encode(Global.encoding) + db_salt.encode(Global.encoding)).hexdigest():
                            return True
                    elif salt_method.lower() == "argon2":
                        try:
                            argon2.verify_password(
                                db_hash.encode(Global.encoding),
                                password_hash.encode(Global.encoding),
                                type=Type.ID
                            )
                        except argon2.exceptions.VerificationError:
                            continue
                        return True
                    else:
                        logging.critical("Salt method is invalid.")
                        raise Exception
            logging.info("\"" + username + "\" tried logging in with wrong password")
        else:
            logging.info("user \"" + username + "\" not found")
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