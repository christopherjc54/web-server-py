#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler
import cgi
import logging
import json

from __main__ import Global, Database
from account import *
from session import *

class DatabaseConnectionLostException(Exception):
    pass

class MissingHeaderException(Exception):
    pass

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

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

    ## still need to do something with this, preferably not compromise the entire system XD
    def do_GET(self):
        self.check_db_connection()

        self.send_response_only(200) ## OK
        self.end_headers()
        self.wfile.write(bytes(Account.get_all_accounts(), Global.encoding))

    def do_POST(self):
        self.check_db_connection()
        form = cgi.FieldStorage(
            fp = self.rfile,
            headers = self.headers,
            environ = {
                'REQUEST_METHOD' : 'POST',
                'CONTENT_TYPE' : self.headers['Content-Type']
            }
        )

        try:
            if form.getvalue("username") == None or form.getvalue("action") == None:
                raise MissingHeaderException

            if(form.getvalue("action") == "CreateAccountSecure" or form.getvalue("action") == "CreateAccountInsecure"):
                is_insecure = ("Insecure" in form.getvalue("action"))
                if (
                    (is_insecure and form.getvalue("password") == None)
                    or (not is_insecure and form.getvalue("passwordHash") == None)
                    or form.getvalue("displayName") == None
                ):
                    raise MissingHeaderException
                return_success, error_message = Account.add(
                    form.getvalue("username"),
                    form.getvalue("password") if is_insecure else form.getvalue("passwordHash"),
                    form.getvalue("displayName"),
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

            if(form.getvalue("action") == "Login"):
                if form.getvalue("passwordHash") == None:
                    raise MissingHeaderException
                if Account.validate(form.getvalue("username"), form.getvalue("passwordHash")):
                    sessionID = Session.create(form.getvalue("username"))
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
                            "errorMessage": "\"" + form.getvalue("username") + "\" already has a session"
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

            ## important security note: sessions are still vulnerable to forgery or replay attacks if not secured with TLS/SSL
            if Session.validate(form.getvalue("username"), form.getvalue("sessionID")):
                if form.getvalue("sessionID") == None:
                    raise MissingHeaderException
                Session.update(form.getvalue("sessionID"))
                ## put secured actions here
                if form.getvalue("action") == "Action":
                    self.send_response_only(200) ## OK
                    self.end_headers()
                    json_response = json.dumps({
                        "message": "test action"
                    })
                    self.wfile.write(bytes(json_response, Global.encoding))
                elif form.getvalue("action") == "Logout":
                    Session.delete(form.getvalue("sessionID"))
                    self.send_response_only(200) ## OK
                    self.end_headers()
                    json_response = json.dumps({
                        "message": "logged out"
                    })
                    self.wfile.write(bytes(json_response, Global.encoding))
                elif form.getvalue("action") == "DeleteAccount":
                    if Account.remove(form.getvalue("username")):
                        self.send_response_only(200) ## OK
                        self.end_headers()
                        json_response = json.dumps({
                            "message": "account deleted"
                        })
                        self.wfile.write(bytes(json_response, Global.encoding))
                    else:
                        self.send_response_only(500) ## Internal Server Error
                        self.end_headers()
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
            self.send_response_only(400) ## Bad Request
            self.end_headers()
            json_response = json.dumps({
                "errorMessage": "please include all required headers"
            })
            self.wfile.write(bytes(json_response, Global.encoding))