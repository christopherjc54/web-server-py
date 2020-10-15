#!/usr/bin/env python3

import logging
import json
import datetime

import mysql.connector
import pyseaweed
import requests

from __main__ import Global
from request_handler import MissingHeaderException
from app_default import AppRequestHandler

class MessengerApp(AppRequestHandler):
    
    possible_actions = (
        "Action",
        "SendMessage",
        "DeleteMessage",
        "GetNewMessages",
        "GetAllMessages",
        "GetFile"
    )
    file_server = None
    file_prefix = "files/"

    def __init__(self):
        logging.getLogger("urllib3").setLevel(logging.WARNING) ## suppress "pyseaweed" module's logging
        self.file_server = pyseaweed.WeedFS(
            master_addr=Global.config.get("miscellaneous", "seaweedfs_address"),
            master_port=Global.config.getint("miscellaneous", "seaweedfs_port"),
            use_session=False,
            use_public_url=True
        )

    @staticmethod
    def on_remove_user(username):
        try:
            Global.cursor.execute(
                "CALL DeleteOrphanMessages(%s);",
                (username,)
            )
            Global.db.commit()
        except mysql.connector.Error as e:
            # Global.db.rollback()
            raise Exception(e.msg)

    def get_file(self, file_id):
        if self.file_server.file_exists(file_id):
            file_contents = self.file_server.get_file(file_id)
            if file_contents is None:
                logging.error("Error getting file.")
                return None
            return file_contents
        else:
            logging.error("File doesn't exist.")
            return None

    def handle_action(self, url_components, query_components, form_data, request):
        try:
            
            if form_data.get("action") == "Action":
                request.send_response_only(200) ## OK
                request.end_headers()
                json_response = json.dumps({
                    "message": "default message action"
                })
                request.wfile.write(bytes(json_response, Global.encoding))
            
            elif form_data.get("action") == "SendMessage":
                if (
                    form_data.get("recipient") == None or
                    form_data.get("messageContent") == None or
                    form_data.get("uploadedFiles") == None
                ):
                    raise MissingHeaderException
                try:
                    Global.cursor.execute(
                        "INSERT INTO Message (messageContent) VALUES (%s);",
                        (form_data.get("messageContent"),)
                    )
                    message_id = Global.cursor.lastrowid
                    for file_name in json.loads(form_data.get("uploadedFiles").replace("'", "\"")):
                        logging.info("Uploading \"" + file_name + "\" to file server.")
                        file_id = None
                        try:
                            file_id = self.file_server.upload_file(stream=form_data.get(self.file_prefix + file_name), name=file_name)
                        except requests.exceptions.ConnectionError:
                            logging.error("Failed to connect to file server.")
                        if file_id is None:
                            logging.error("Failed to upload \"" + file_name + "\".")
                            raise mysql.connector.Error
                        Global.cursor.execute(
                            "INSERT INTO File (messageID, fileName, fileID) VALUES (%s, %s, %s);",
                            (message_id, file_name, file_id)
                        )
                    Global.cursor.execute(
                        "INSERT INTO SentItem (username, messageID) VALUES (%s, %s);",
                        (form_data.get("username"), message_id)
                    )
                    Global.cursor.execute(
                        "INSERT INTO Inbox (username, messageID) VALUES (%s, %s);",
                        (form_data.get("recipient"), message_id)
                    )
                    Global.db.commit()
                    request.send_response_only(200) ## OK
                    request.end_headers()
                    json_response = json.dumps({
                        "message": "successfully sent message",
                        "messageID": message_id
                    })
                    request.wfile.write(bytes(json_response, Global.encoding))
                except mysql.connector.Error as e:
                    Global.db.rollback()
                    logging.error("Error adding message to database.")
                    if "Unknown error" not in e.msg :
                        logging.error(e)
                    request.send_response_only(500) ## Internal Server Error
                    request.end_headers()
            
            elif form_data.get("action") == "DeleteMessage":
                raise NotImplementedError
                if self.file_server.file_exists(file_id):
                    self.file_server.delete_file(file_id)
                    self.file_server.vacuum()
            
            elif form_data.get("action") == "GetNewMessages":
                raise NotImplementedError
                file = self.get_file(file_id)
                if file is None:
                    pass
            
            elif form_data.get("action") == "GetAllMessages":
                raise NotImplementedError
                file = self.get_file(file_id)
                if file is None:
                    pass

            elif form_data.get("action") == "GetFile":
                raise NotImplementedError
                file = self.get_file(file_id)
                if file is None:
                    pass
        
        except NotImplementedError:
                request.send_response_only(501) ## Not Implemented
                request.end_headers()
                json_response = json.dumps({
                    "errorMessage": "coming to a server near you!"
                })
                request.wfile.write(bytes(json_response, Global.encoding))