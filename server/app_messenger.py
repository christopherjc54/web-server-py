#!/usr/bin/env python3

import mysql.connector
import logging
import json

from __main__ import Global
from request_handler import MissingHeaderException
from app_default import AppRequestHandler

class MessengerAppRequestHandler(AppRequestHandler):
    
    possible_actions = ( ## tuples with one item should have a comma
        "Message",
    )

    def on_remove_user(username):
        try:
            Global.cursor.execute(
                "CALL DeleteOrphanMessages(%s);",
                (username,)
            )
            Global.db.commit()
        except mysql.connector.Error as e:
            logging.critical(e.msg)
            Global.db.rollback()

    def handle(self, request, input_action):
        if input_action == "Message":
            request.send_response_only(200) ## OK
            request.end_headers()
            json_response = json.dumps({
                "message": "message action"
            })
            request.wfile.write(bytes(json_response, Global.encoding))