#!/usr/bin/env python3

import mysql.connector
import logging
import json

from __main__ import Global
from request_handler import MissingHeaderException ## should be used in custom apps

## contains required methods, custom apps must inherit or override them
class AppRequestHandler:

    possible_actions = ( ## tuples with one item should have a comma
        "Action",
    )

    def has_action(self, input_action):
        for action in self.possible_actions:
            if input_action.lower() == action.lower():
                return True
        return False
    
    def on_remove_user():
        pass

    def handle_action(self, request, input_action):
        if input_action == "Action":
            request.send_response_only(200) ## OK
            request.end_headers()
            json_response = json.dumps({
                "message": "default action"
            })
            request.wfile.write(bytes(json_response, Global.encoding))