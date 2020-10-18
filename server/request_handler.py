#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler
import cgi
import logging
import json
import urllib
import os

from __main__ import Global, Database
from account import *
from session import *

class DatabaseConnectionLostException(Exception):
    pass

class MissingHeaderException(Exception):
    pass

class RequestHandler(BaseHTTPRequestHandler):

    possible_action = (
        "CreateAccountSecure",
        "CreateAccountInsecure",
        "Login",
        "Logout",
        "DeleteAccount"
    )

    def check_db_connection(self):
        ## try to reconnect
        if not Global.db.is_connected():
            logging.error("Lost connection to database, reconnecting...")
            Database.connect()
        ## connection was permanently lost
        if not Global.db.is_connected():
            logging.error("Failed to reconnect.")
            self.send_response_only(500) ## Internal Server Error
            self.end_headers()
            raise DatabaseConnectionLostException

    def get_request_parameters(self, getFormData=False):
        show_request_data = Global.config.getboolean("log", "show_request_data")
        longest_width = 22

        if("?" in self.path):
            url_components = self.path.split("?")[0]
        else:
            url_components = self.path
        if(url_components.endswith("/")):
            url_components = url_components.split("/")[1:-1]
        else:
            url_components = url_components.split("/")[1:]
        if show_request_data:
            logging.debug("URL path components: ".ljust(longest_width) + str(url_components))
        
        query_components = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        for component in query_components:
            query_components.update({ component : query_components[component][0] })
        if show_request_data:
            logging.debug("URL query components: ".ljust(longest_width) + str(query_components))
        
        if getFormData:
            form = cgi.FieldStorage(
                fp = self.rfile,
                headers = self.headers,
                environ = {
                    'REQUEST_METHOD' : 'POST',
                    'CONTENT_TYPE' : self.headers['Content-Type']
                }
            )
            form_data = dict()
            for item in form:
                form_data.update({ item : form[item].value })
            if show_request_data:
                logging.debug("Form data: ".ljust(longest_width) + str(form_data))
            return url_components, query_components, form_data
        else:
            return url_components, query_components

    def do_GET(self):
        self.check_db_connection()
        url_components, query_components = self.get_request_parameters(getFormData=False)
        self.handle_action("GET", url_components, query_components, None)

    def do_POST(self):
        self.check_db_connection()
        url_components, query_components, form_data = self.get_request_parameters(getFormData=True)
        self.handle_action("POST", url_components, query_components, form_data)

    def handle_action(self, method, url_components, query_components, form_data):
        if method == "POST":
            try:
                if form_data.get("username") == None or form_data.get("action") == None:
                    logging.info("Received invalid request.")
                    raise MissingHeaderException

                is_valid_action = False
                for action in self.possible_action + Global.app_handler.possible_actions:
                    if form_data.get("action") == action:
                        is_valid_action = True
                logging.info("Received " + ("valid" if is_valid_action else "invalid") + " \"" + form_data.get("action") + "\" request.")

                if(form_data.get("action") == "CreateAccountSecure" or form_data.get("action") == "CreateAccountInsecure"):
                    is_insecure = ("Insecure" in form_data.get("action"))
                    if (
                        (is_insecure and form_data.get("password") == None)
                        or (not is_insecure and form_data.get("passwordHash") == None)
                        or form_data.get("displayName") == None
                    ):
                        raise MissingHeaderException
                    return_success, error_message = Account.add(
                        form_data.get("username"),
                        form_data.get("password") if is_insecure else form_data.get("passwordHash"),
                        form_data.get("displayName"),
                        plain_text=is_insecure
                    )
                    if return_success:
                        self.send_response_only(201) ## Created
                        self.end_headers()
                        json_response = json.dumps({
                            "message": "account succesfuly created"
                        })
                        self.wfile.write(bytes(json_response, Global.encoding))
                    else:
                        self.send_response_only(403) ## Forbidden
                        self.end_headers()
                        json_response = json.dumps({
                            "errorMessage": error_message
                        })
                        self.wfile.write(bytes(json_response, Global.encoding))
                    return

                if(form_data.get("action") == "Login"):
                    if form_data.get("passwordHash") == None:
                        raise MissingHeaderException
                    if Account.validate(form_data.get("username"), form_data.get("passwordHash")):
                        sessionID = Session.create(form_data.get("username"))
                        if sessionID != "":
                            self.send_response_only(200) ## OK
                            self.end_headers()
                            json_response = json.dumps({
                                "message": "successfully logged in",
                                "sessionID": sessionID
                            })
                            self.wfile.write(bytes(json_response, Global.encoding))
                        else:
                            self.send_response_only(403) ## Forbidden
                            self.end_headers()
                            json_response = json.dumps({
                                "errorMessage": "\"" + form_data.get("username") + "\" already has a session"
                            })
                            self.wfile.write(bytes(json_response, Global.encoding))
                    else:
                        self.send_response_only(401) ## Unauthorized
                        self.end_headers()
                        json_response = json.dumps({
                            "errorMessage": "valid credentials not provided"
                        })
                        self.wfile.write(bytes(json_response, Global.encoding))
                    return

                ## important security note: credentials and sessions are vulnerable to forgery or replay attacks if not secured with TLS/SSL
                if Session.validate(form_data.get("username"), form_data.get("sessionID")):
                    if form_data.get("sessionID") == None:
                        raise MissingHeaderException
                    Session.update(form_data.get("sessionID"))
                    if form_data.get("action") == "Logout":
                        Session.delete(form_data.get("sessionID"))
                        self.send_response_only(200) ## OK
                        self.end_headers()
                        json_response = json.dumps({
                            "message": "logged out"
                        })
                        self.wfile.write(bytes(json_response, Global.encoding))
                    elif form_data.get("action") == "DeleteAccount":
                        try:
                            Global.app_handler.on_remove_user(form_data.get("username")) ## cleanup app-specific user data
                            Account.remove(form_data.get("username"))
                            self.send_response_only(200) ## OK
                            self.end_headers()
                            json_response = json.dumps({
                                "message": "account deleted"
                            })
                            self.wfile.write(bytes(json_response, Global.encoding))
                        except Exception as e:
                            logging.critical(e)
                            self.send_response_only(500) ## Internal Server Error
                            self.end_headers()
                    ## pass secured actions to app-specific request handler
                    elif is_valid_action:
                        Global.app_handler.handle_action(url_components, query_components, form_data, self)
                    else:
                        self.send_response_only(400) ## Bad Request
                        self.end_headers()
                else:
                    self.send_response_only(401) ## Unauthorized
                    self.end_headers()
                    json_response = json.dumps({
                        "errorMessage": "valid sessionID not provided"
                    })
                    self.wfile.write(bytes(json_response, Global.encoding))
        
            except MissingHeaderException:
                logging.info("Request was missing headers.")
                self.send_response_only(400) ## Bad Request
                self.end_headers()
                json_response = json.dumps({
                    "errorMessage": "please include all required headers"
                })
                self.wfile.write(bytes(json_response, Global.encoding))

        ## still need to do something with this, preferably not compromise the entire system XD
        elif method == "GET":
            self.send_response_only(200) ## OK
            self.end_headers()
            self.wfile.write(bytes(Account.get_all_as_string(), Global.encoding))

        else:
            self.send_response_only(501) ## Not Implemented
            self.end_headers()