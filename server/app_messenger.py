#!/usr/bin/env python3

import mysql.connector
import logging
import json

from __main__ import Global
from request_handler import MissingHeaderException
from app_default import AppRequestHandler

class MessengerAppRequestHandler(AppRequestHandler):
    
    possible_actions = ( ## tuples with one item should have a comma
        "Action"
        "SendMessage",
        "GetNewMessages",
        "GetAllMessages"
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
            raise Exception

    def handle_action(self, request, input_action):
        try:
            
            if input_action == "Message":
                request.send_response_only(200) ## OK
                request.end_headers()
                json_response = json.dumps({
                    "message": "default message action"
                })
                request.wfile.write(bytes(json_response, Global.encoding))
            
            elif input_action == "SendMessage":
                raise NotImplementedError
            
            elif input_action == "GetNewMessages":
                raise NotImplementedError
            
            elif input_action == "GetAllMessages":
                raise NotImplementedError
        
        except NotImplementedError:
                request.send_response_only(501) ## Not Implemented
                request.end_headers()
                json_response = json.dumps({
                    "errorMessage": "coming to a server near you!"
                })
                request.wfile.write(bytes(json_response, Global.encoding))