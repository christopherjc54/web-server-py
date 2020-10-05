#!/usr/bin/env python3

from os import stat
import mysql.connector
import random, string
import datetime
import logging

from __main__ import Global

class Session:

    @staticmethod
    def create(username, datetime_offset=datetime.timedelta(days=1, hours=0)):
        sessionID = ''.join(random.SystemRandom().choice(string.hexdigits) for _ in range(32))
        expDateTime = datetime.datetime.now() + datetime_offset
        try:
            Global.cursor.execute(
                "INSERT INTO Session (username, sessionID, expDateTime) VALUES (%s, %s, %s);",
                (username, sessionID, expDateTime)
            )
            Global.db.commit()
        except mysql.connector.errors.IntegrityError: ## used for duplicate key errors, foreign key constraint errors (n/a here), and data too long errors (n/a here)
            return "" ## session already exists
                      ## this error will only occur when Session("username") is set as primary key or unique
        return sessionID

    @staticmethod
    def validate(username, sessionID):
        Global.cursor.execute(
            "SELECT sessionID, expDateTime FROM Session WHERE username = %s AND sessionID = %s;",
            (username, sessionID)
        )
        result = Global.cursor.fetchall()
        if len(result) > 0:
            for db_sessionID, db_expDateTime in result:
                if(db_expDateTime > datetime.datetime.now()):
                    return True
                else:
                    logging.info("deleting an expired session for \"" + username + "\"")
                    Session.delete(db_sessionID)
            logging.error("all sessions for \"" + username + "\" expired")
        else:
            logging.error("session not found")
        return False

    @staticmethod
    def update(sessionID, datetime_offset=datetime.timedelta(days=1, hours=0)):
        expDateTime = datetime.datetime.now() + datetime_offset
        Global.cursor.execute(
            "UPDATE Session SET expDateTime = %s WHERE sessionID = %s;",
            (expDateTime, sessionID)
        )
        Global.db.commit()

    @staticmethod
    def delete(sessionID):
        Global.cursor.execute(
            "DELETE FROM Session WHERE sessionID = %s;",
            (sessionID,)
        )
        Global.db.commit()

    @staticmethod
    def delete_all_expired():
        Global.cursor.execute("SELECT username, sessionID, expDateTime FROM Session;")
        result = Global.cursor.fetchall()
        for db_username, db_sessionID, db_expDateTime in result:
            if(db_expDateTime < datetime.datetime.now()):
                logging.info("deleting an expired session for \"" + db_username + "\"")
                Session.delete(db_sessionID)

    @staticmethod
    def test(username):
        expDateTimeSQL = "SELECT expDateTime FROM Session WHERE sessionID = %s;"

        sessionID = Session.create(username)
        Global.cursor.execute(expDateTimeSQL, (sessionID,))
        result = Global.cursor.fetchall()
        logging.debug("sessionID: " + sessionID)
        logging.debug("expDateTime: " + str(result[0][0]))
        logging.debug("valid session? " + str(Session.validate(username, sessionID)))

        Session.update(sessionID, datetime.timedelta(days=2))
        Global.cursor.execute(expDateTimeSQL, (sessionID,))
        result = Global.cursor.fetchall()
        logging.debug("expDateTime: " + str(result[0][0]))
        logging.debug("valid session? " + str(Session.validate(username, sessionID)))

        Session.update(sessionID, datetime.timedelta(days=-5))
        Global.cursor.execute(expDateTimeSQL, (sessionID,))
        result = Global.cursor.fetchall()
        logging.debug("expDateTime: " + str(result[0][0]))
        logging.debug("valid session? " + str(Session.validate(username, sessionID)))

        Session.delete(sessionID)
        logging.debug("valid session? " + str(Session.validate(username, sessionID)))