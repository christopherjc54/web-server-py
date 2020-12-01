#!/usr/bin/env python3

import logging
import json
import base64

import mysql.connector
import pyseaweed
import requests

from __main__ import Global
from request_handler import MissingHeaderException
from app_default import AppRequestHandler

class BooleanTypeError(Exception):
    pass

class MessengerApp(AppRequestHandler):
    
    possible_actions = (
        "Action",
        "SendMessage",
        "GetMessages",
        "MarkAsRead",
        "DeleteMessage"
    )
    file_server = None

    def __init__(self):
        logging.getLogger("urllib3").setLevel(logging.WARNING) ## suppress "pyseaweed" module's logging
        self.file_server = pyseaweed.WeedFS(
            master_addr=Global.config.get("miscellaneous", "seaweedfs_address"),
            master_port=Global.config.getint("miscellaneous", "seaweedfs_port"),
            use_session=False,
            use_public_url=False
        )

    def on_remove_user(self, username):
        try:
            Global.cursor.start_transaction()
            Global.cursor.execute(
                "DELETE FROM Sent WHERE fromUsername = %s;",
                (username,)
            )
            Global.cursor.execute(
                "DELETE FROM Inbox WHERE toUsername = %s;",
                (username,)
            )
            Global.db.commit()
            self.delete_orphan_messages()
        except mysql.connector.Error as e:
            Global.db.rollback()
            raise Exception(e.msg)

    def delete_orphan_messages(self):
        Global.cursor.execute(
            """
                SELECT m.id
                FROM Message m
                WHERE NOT EXISTS (
                    SELECT TRUE
                    FROM Sent s
                    WHERE m.id = s.messageID
                ) AND NOT EXISTS (
                    SELECT TRUE
                    FROM Inbox i
                    WHERE m.id = i.messageID
                )
                ORDER BY id;
            """
        )
        orphan_message_result = Global.cursor.fetchall()
        deleted_message_count = 0
        for db_messageID in orphan_message_result:
            try:
                Global.cursor.start_transaction()
                Global.cursor.execute(
                    "SELECT id, remoteFileID FROM File WHERE messageID = %s ORDER BY id;",
                    (db_messageID[0],)
                )
                file_result = Global.cursor.fetchall()
                for db_fileID, db_remoteFileID in file_result:
                    if not self.file_server.file_exists(db_remoteFileID):
                        logging.error("Orphan file doesn't exist.")
                        raise mysql.connector.Error
                for db_fileID, db_remoteFileID in file_result:
                    if self.file_server.delete_file(db_remoteFileID):
                        Global.cursor.execute(
                            "DELETE FROM File WHERE id = %s;",
                            (db_fileID,)
                        )
                    else: ## this error will result in a corrupt state, but is not likely
                        logging.error("Error deleting remote orphan file.")
                        raise mysql.connector.Error
                Global.cursor.execute(
                    "DELETE FROM Message WHERE id = %s;",
                    (db_messageID[0],)
                )
                Global.db.commit()
                deleted_message_count += 1
            except mysql.connector.Error as e:
                Global.db.rollback()
                if "Unknown error" not in e.msg:
                    logging.error(e.msg)
                logging.error("Error deleting orphan message with ID " + db_messageID + ".")
        self.file_server.vacuum()
        if deleted_message_count == len(orphan_message_result):
            logging.info("Successfully deleted all orphan message" + ("s" if len(orphan_message_result) > 1 else "") + ".")
        else:
            logging.info("Deleted " + deleted_message_count + "/" + (len(orphan_message_result) - deleted_message_count) + " orphan message" + ("s" if len(orphan_message_result) > 1 else "") + ".")


    @staticmethod
    def get_bool(input):
        if input.lower() == "true" or input == "1":
            return True
        elif input.lower() == "false" or input == "0":
            return False
        else:
            raise BooleanTypeError

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
                    form_data.get("recipients") == None or
                    form_data.get("messageContent") == None or
                    form_data.get("uploadedFiles") == None or
                    form_data.get("fileContent") == None
                ):
                    raise MissingHeaderException

                try:
                    Global.cursor.start_transaction()
                    Global.cursor.execute(
                        "INSERT INTO Message (messageContent) VALUES (%s);",
                        (form_data.get("messageContent"),)
                    )
                    message_id = Global.cursor.lastrowid
                    recipients = json.loads(form_data.get("recipients"))
                    for recipient in [ele for index, ele in enumerate(recipients) if ele not in recipients[:index]]:
                        Global.cursor.execute(
                            "SELECT TRUE FROM Account WHERE username = %s;",
                            (recipient,)
                        )
                        if len(Global.cursor.fetchall()) == 0:
                            Global.db.rollback()
                            logging.error("Invalid recipient.")
                            request.send_response_only(400) ## Bad Request
                            request.end_headers()
                            json_response = json.dumps({
                                "errorMessage": "\"" + recipient + "\" is not a valid account name"
                            })
                            request.wfile.write(bytes(json_response, Global.encoding))
                            return
                        Global.cursor.execute(
                            "INSERT INTO Sent (fromUsername, toUsername, messageID) VALUES (%s, %s, %s);",
                            (form_data.get("username"), recipient, message_id)
                        )
                        Global.cursor.execute(
                            "INSERT INTO Inbox (fromUsername, toUsername, messageID) VALUES (%s, %s, %s);",
                            (form_data.get("username"), recipient, message_id)
                        )
                    file_content = json.loads(form_data.get("fileContent"))
                    for file_name in json.loads(form_data.get("uploadedFiles")):
                        logging.info("Uploading \"" + file_name + "\" to file server.")
                        file_id = None
                        try:
                            file_id = self.file_server.upload_file(stream=base64.b64decode(file_content[file_name]), name=file_name)
                        except requests.exceptions.ConnectionError:
                            logging.error("Failed to connect to file server.")
                        if file_id is None:
                            logging.error("Failed to upload \"" + file_name + "\".")
                            raise mysql.connector.Error
                        logging.info("Successfully uploaded file.")
                        Global.cursor.execute(
                            "INSERT INTO File (messageID, fileName, remoteFileID) VALUES (%s, %s, %s);",
                            (message_id, file_name, file_id)
                        )
                    del file_content
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
                    if "Unknown error" not in e.msg:
                        logging.error(e)
                    request.send_response_only(500) ## Internal Server Error
                    request.end_headers()
                del form_data

            elif form_data.get("action") == "GetMessages":
                if form_data.get("getFileContent") == None or form_data.get("getOneMessage") == None:
                    raise MissingHeaderException
                get_file_content = self.get_bool(form_data.get("getFileContent"))
                get_one_message = self.get_bool(form_data.get("getOneMessage"))
                get_only_new_messages = False
                if get_one_message:
                    if form_data.get("messageID") == None:
                        raise MissingHeaderException
                else:
                    if form_data.get("getOnlyNewMessages") == None:
                        raise MissingHeaderException
                    get_only_new_messages = self.get_bool(form_data.get("getOnlyNewMessages"))

                try:
                    Global.cursor.execute(
                        """
                            SELECT i.messageID, i.fromUsername, m.messageContent, m.sentDateTime, i.messageRead
                            FROM Inbox i, Message m
                            WHERE i.toUsername = %s AND i.messageID = m.id
                            """ + (("AND m.id = " + str(int(form_data.get("messageID")))) if get_one_message else "") + """
                            """ + ("AND i.messageRead = false" if get_only_new_messages else "") +  """
                            ORDER BY m.id;
                        """,
                        (form_data.get("username"), )
                    )
                    response_messages = Global.cursor.fetchall()
                    message_list = list()
                    for db_messageID, db_fromUsername, db_messageContent, db_sentDateTime, db_messageRead in response_messages:
                        Global.cursor.execute(
                            "SELECT id, fileName, remoteFileID FROM File WHERE messageID = %s ORDER BY id;",
                            (db_messageID,)
                        )
                        response_files = Global.cursor.fetchall()
                        file_list = list()
                        try:
                            for db_fileID, db_fileName, db_remoteFileID in response_files:
                                file_list.append({
                                    "fileID": db_fileID,
                                    "fileName": db_fileName,
                                    "fileContent": (str(base64.b64encode(self.get_file(db_remoteFileID)), encoding=Global.encoding) if get_file_content else None)
                                })
                        except requests.exceptions.ConnectionError:
                            logging.error("Failed to connect to file server.")
                            raise mysql.connector.Error
                        message_list.append({
                            "messageID" : db_messageID,
                            "fromUsername": db_fromUsername,
                            "messageContent": db_messageContent,
                            "sentDateTime": str(db_sentDateTime),
                            "messageRead": db_messageRead,
                            "fileList": file_list
                        })
                        del file_list
                    request.send_response_only(200) ## OK
                    request.end_headers()
                    json_response = json.dumps({
                        "message": "successfully retrieved message" + ("s" if not get_one_message else ""),
                        "messages": message_list
                    })
                    del message_list
                    request.wfile.write(bytes(json_response, Global.encoding))
                    del json_response
                except mysql.connector.Error as e:
                    logging.error("Error getting message" + ("s" if not get_one_message else "") + ".")
                    if "Unknown error" not in e.msg:
                        logging.error(e)
                    request.send_response_only(500) ## Internal Server Error
                    request.end_headers()

            elif form_data.get("action") == "MarkAsRead":
                if form_data.get("messageID") == None or form_data.get("messageRead") == None:
                    raise MissingHeaderException
                message_read = self.get_bool(form_data.get("messageRead"))

                try:
                    Global.cursor.execute(
                        "UPDATE Inbox SET messageRead = %s WHERE toUsername = %s AND messageID = %s;",
                        (("1" if message_read else "0"), form_data.get("username"), form_data.get("messageID"))
                    )
                    request.send_response_only(200) ## OK
                    request.end_headers()
                    json_response = json.dumps({
                        "message": "updated message read flag"
                    })
                    request.wfile.write(bytes(json_response, Global.encoding))
                except mysql.connector.Error as e:
                    logging.error(e.msg)
                    logging.error("Error marking message as " + ("read" if message_read else "unread") + ".")
                    request.send_response_only(500) ## Internal Server Error
                    request.end_headers()

            elif form_data.get("action") == "DeleteMessage":
                if form_data.get("messageID") == None or form_data.get("mailboxType") == None:
                    raise MissingHeaderException

                try:
                    if form_data.get("mailboxType") == "Sent":
                        delete_query = "DELETE FROM Sent WHERE fromUsername = %s AND messageID = %s;"
                    elif form_data.get("mailboxType") == "Inbox":
                        delete_query = "DELETE FROM Inbox WHERE toUsername = %s AND messageID = %s;"
                    else:
                        request.send_response_only(400) ## Bad Request
                        request.end_headers()
                        json_response = json.dumps({
                            "errorMessage": "invalid mailbox"
                        })
                        request.wfile.write(bytes(json_response, Global.encoding))
                        return
                    Global.cursor.execute(
                        delete_query,
                        (form_data.get("username"), form_data.get("messageID"))
                    )
                    if Global.cursor.rowcount == 0:
                        request.send_response_only(400) ## Bad Request
                        request.end_headers()
                        json_response = json.dumps({
                            "errorMessage": "message not found"
                        })
                        request.wfile.write(bytes(json_response, Global.encoding))
                        return
                    self.delete_orphan_messages()
                    request.send_response_only(200) ## OK
                    request.end_headers()
                    json_response = json.dumps({
                        "message": "successfully deleted message"
                    })
                    request.wfile.write(bytes(json_response, Global.encoding))
                except mysql.connector.Error:
                    logging.error("Error deleting message.")
                    request.send_response_only(500) ## Internal Server Error
                    request.end_headers()

        except BooleanTypeError:
            logging.error("BooleanTypeError occured.")
            request.send_response_only(400) ## Bad Request
            request.end_headers()

        except NotImplementedError:
            request.send_response_only(501) ## Not Implemented
            request.end_headers()
            json_response = json.dumps({
                "errorMessage": "coming to a server near you!"
            })
            request.wfile.write(bytes(json_response, Global.encoding))