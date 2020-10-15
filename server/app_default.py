#!/usr/bin/env python3

## missing imports should be used in custom apps

import logging
import json

import mysql.connector

from __main__ import Global
from request_handler import MissingHeaderException

## contains required methods, custom apps must inherit or override them
class AppRequestHandler:

    possible_actions = ( ## tuples with one item should have a comma
        "Action",
    )
    
    @staticmethod
    def on_remove_user(username):
        pass

    def handle_action(self, url_components, query_components, form_data, request):
        if form_data.get("action") == "Action":
            request.send_response_only(200) ## OK
            request.end_headers()
            json_response = json.dumps({
                "message": "default action"
            })
            request.wfile.write(bytes(json_response, Global.encoding))