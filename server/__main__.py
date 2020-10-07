#!/usr/bin/env python3

from http.server import ThreadingHTTPServer
from pydoc import locate
import ssl
import mysql.connector
import hashlib
import logging
import configparser
import os.path

## classes in main must be defined before project imports to avoid circular import errors

## program globals
class Global(object):

    db = None
    cursor = None
    encoding = "utf-8"
    config = None
    app_handler = None

class Database:

    def connect():
        try:
            Global.db = mysql.connector.connect(
                host=Global.config.get("database", "address"),
                user=Global.config.get("database", "username"),
                password=Global.config.get("database", "password"),
                database=Global.config.get("database", "name")
            )
            Global.cursor = Global.db.cursor()
            logging.info("Connected to database.")
        except Exception as e:
            logging.critical(e)
            logging.critical("Couldn't connect to database.")

from account import *
from session import *
from request_handler import *

## server globals
config_filename = "config.ini"

## setup
logging.basicConfig(format='%(levelname)-8s: %(message)s', level=logging.DEBUG)
# logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)
Global.config = configparser.ConfigParser(comment_prefixes="#", inline_comment_prefixes="#")
Global.config.setdefault("server", {
    "run_tests_on_startup": "false",
    "address": "localhost",
    "port": "443",
    "ssl_enabled": "true",
    "ssl_key_file": "private_key.pem",
    "ssl_cert_file": "cert.pem"
})
Global.config.setdefault("database", {
    "address": "localhost",
    "username" : "username",
    "password": "password",
    "name": "database"
})
Global.config.setdefault("app_request_handler", {
    "module_name": "app_default",
    "class_name": "AppRequestHandler"
})
Global.config.setdefault("miscellaneous", {
    "salt_method": "SHA3-512",
    "salt_method_auto_read": "true"
})
try:
    if not os.path.exists(config_filename):
        raise Exception
    Global.config.read(config_filename)
except:
    logging.critical("Couldn't read config file.")
    exit(-1)
handler_class = locate(Global.config.get("app_request_handler", "module_name") + "." + Global.config.get("app_request_handler", "class_name"))
Global.app_handler = handler_class()
Database.connect()
if not (Global.db and Global.cursor):
    exit(-1)
Session.delete_all_expired()

## test code
if Global.config.getboolean("server", "run_tests_on_startup"):
    test_username, test_password = "testaccount", "badpassword1"
    Account.add(test_username, test_password, "John Doe")
    logging.debug("test account validated? " + str(Account.validate(test_username, hashlib.sha3_512(test_password.encode(Global.encoding)).hexdigest())))
    print()
    Session.test(test_username)
    print()
    Account.remove(test_username)

## run http(s) server
httpd = None
try:
    httpd = ThreadingHTTPServer((Global.config.get("server", "address"), Global.config.getint("server", "port")), SimpleHTTPRequestHandler)
    ssl_enabled = Global.config.getboolean("server", "ssl_enabled")
    if ssl_enabled:
        httpd.socket = ssl.wrap_socket(
            httpd.socket,
            keyfile=Global.config.get("server", "ssl_key_file"),
            certfile=Global.config.get("server", "ssl_cert_file"),
            server_side=True
        )
    logging.info("Waiting for HTTP" + ("S" if ssl_enabled else "") + " requests...")
    httpd.serve_forever()
except DatabaseConnectionLostException:
    pass ## shutdown server since all it does is handle db related requests
except KeyboardInterrupt:
    print() ## put bash shell's "^C" on its own line
except Exception as e:
    logging.critical(e.msg)
## make sure sockets and db close properly
if httpd is not None:
    httpd.server_close()
    logging.info("Closed HTTPS server.")
if Global.cursor is not None:
    Global.cursor.close()
if Global.db is not None:
    Global.db.close()
    logging.info("Closed database connection.")