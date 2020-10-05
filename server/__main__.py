#!/usr/bin/env python3

from http.server import ThreadingHTTPServer
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

class Database:

    def connect():
        try:
            Global.db = mysql.connector.connect(
                host=config.get("database", "address"),
                user=config.get("database", "username"),
                password=config.get("database", "password"),
                database=config.get("database", "name")
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
httpd = None
config = None
config_filename = "config.ini"

## setup
logging.basicConfig(format='%(levelname)-8s: %(message)s', level=logging.DEBUG)
# logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)
config = configparser.ConfigParser(comment_prefixes="#", inline_comment_prefixes="#")
config.setdefault("database", {
    "address": "localhost",
    "username" : "username",
    "password": "password",
    "name": "database"
})
config.setdefault("server", {
    "run_tests_on_startup": "false",
    "address": "localhost",
    "port": "443",
    "ssl_key_file": "private_key.pem",
    "ssl_cert_file": "cert.pem"
})
try:
    if not os.path.exists(config_filename):
        raise Exception
    config.read(config_filename)
except:
    logging.critical("Couldn't read config file.")
    exit(-1)
Database.connect()
if not (Global.db or Global.cursor):
    exit(-1)
Session.delete_all_expired()

## test code
if config.getboolean("server", "run_tests_on_startup"):
    test_username, test_password = "testaccount", "badpassword1"
    Account.add(test_username, test_password, "John Doe")
    logging.debug("test account validated? " + str(Account.validate(test_username, hashlib.sha256(test_password.encode(Global.encoding)).hexdigest())))
    print()
    Session.test(test_username)
    print()
    Account.remove(test_username)

## run https server
try:
    httpd = ThreadingHTTPServer((config.get("server", "address"), config.getint("server", "port")), SimpleHTTPRequestHandler)
    httpd.socket = ssl.wrap_socket(
        httpd.socket,
        keyfile=config.get("server", "ssl_key_file"),
        certfile=config.get("server", "ssl_cert_file"),
        server_side=True
    )
    logging.info("Waiting for HTTPS requests...")
    httpd.serve_forever()
## shutdown server since all it does is handle db related requests
except DatabaseConnectionLostException:
    pass
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