#!/usr/bin/env python3

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import ssl
import cgi
import mysql.connector
import random, string
import hashlib
import datetime
import logging
import json

## globals
httpd = None
db = None
cursor = None
encoding = "utf-8"

## config
db_address = "localhost"
db_username = "user"
db_password = "1234"
db_name = "DatabaseServer"
run_tests_on_startup = True
server_address = "localhost"
server_port = 4443 ## need to run with sudo to use port 443, otherwise use port 1024+
ssl_cert_file = "cert.pem"
ssl_key_file = "private_key.pem"

def add_user_account(username, original_password, display_name, plain_text=True):
    cursor.execute(
        "SELECT * FROM Account WHERE username = %s",
        (username,)
    )
    result = cursor.fetchall()
    if len(result) > 0:
        error_message = "user \"" + username + "\" already exists"
        logging.error(error_message)
        return False, error_message
    salt = ''.join(random.SystemRandom().choice(string.hexdigits) for _ in range(16))
    if plain_text:
        hashed_password = hashlib.sha256(original_password.encode(encoding)).hexdigest()
    else:
        hashed_password = original_password
    hash = hashlib.sha256(hashed_password.encode(encoding) + salt.encode(encoding)).hexdigest()
    try:
        cursor.execute(
            "INSERT INTO Account (username, displayName, salt, hash) VALUES (%s, %s, %s, %s);",
            (username, display_name, salt, hash)
        )
        db.commit() ## would need exception check and db.rollback() if one of many commits fail (ACID property)
    except mysql.connector.DataError as e:
        assert "data too long" in e.msg.lower()
        error_message = "username must be 15 or less characters"
        logging.error(error_message)
        return False, error_message

    print()
    logging.debug("Added new account to database:")
    logging.debug("  Username: " + username)
    if plain_text:
        logging.debug("  Password: " + original_password)
    logging.debug("  Hashed Password: " + hashed_password)
    logging.debug("  Salt: " + salt)
    logging.debug("  Hash: " + hash)
    print()

    return True, ""

def remove_user_account(username):
    try:
        cursor.execute(
            "DELETE FROM Session WHERE username = %s;",
            (username,)
        )
        cursor.execute(
            "DELETE FROM Account WHERE username = %s;",
            (username,)
        )
        cursor.execute(
            "CALL DeleteOrphanMessages(%s);",
            (username,)
        )
        db.commit()
        return True
    except mysql.connector.Error as e:
        logging.critical(e.msg)
        db.rollback()
    return False

def get_all_accounts():
    cursor.execute("SELECT username, displayName, salt, hash FROM Account;")
    result = cursor.fetchall()
    if len(result) > 0:
        account_str = ""
        for index, (db_username, db_display_name, db_salt, db_hash) in enumerate(result):
            account_str += "Username: " + db_username
            account_str += "\n" + "Display Name: " + db_display_name
            # account_str += "\n" + "Salt: " + db_salt
            # account_str += "\n" + "Hash: " + db_hash
            if index < len(result) - 1:
                account_str += "\n\n"
        return account_str
    else:
        return "no accounts found"

def validate_credentials(username, password_hash):
    cursor.execute(
        "SELECT username, salt, hash FROM Account WHERE username = %s;",
        (username,)
    )
    result = cursor.fetchall()
    if len(result) > 0:
        for db_username, db_salt, db_hash in result:
            salted_hash = hashlib.sha256(password_hash.encode(encoding) + db_salt.encode(encoding)).hexdigest()
            if db_username == username and db_hash == salted_hash:
                return True
        logging.error("\"" + username + "\" tried logging in with wrong password")
    else:
        logging.error("user \"" + username + "\" not found")
    return False

def create_session(username, datetime_offset=datetime.timedelta(days=1, hours=0)):
    sessionID = ''.join(random.SystemRandom().choice(string.hexdigits) for _ in range(32))
    expDateTime = datetime.datetime.now() + datetime_offset
    try:
        cursor.execute(
            "INSERT INTO Session (username, sessionID, expDateTime) VALUES (%s, %s, %s);",
            (username, sessionID, expDateTime)
        )
        db.commit()
    except mysql.connector.errors.IntegrityError: ## used for duplicate key errors, foreign key constraint errors (n/a here), and data too long errors (n/a here)
        return "" ## session already exists
                  ## this error will only occur when Session("username") is set as primary key or unique
    return sessionID

def validate_session(username, sessionID):
    cursor.execute(
        "SELECT sessionID, expDateTime FROM Session WHERE username = %s AND sessionID = %s;",
        (username, sessionID)
    )
    result = cursor.fetchall()
    if len(result) > 0:
        for db_sessionID, db_expDateTime in result:
            if(db_expDateTime > datetime.datetime.now()):
                return True
            else:
                logging.info("deleting an expired session for \"" + username + "\"")
                delete_session(db_sessionID)
        logging.error("all sessions for \"" + username + "\" expired")
    else:
        logging.error("session not found")
    return False

def update_session(sessionID, datetime_offset=datetime.timedelta(days=1, hours=0)):
    expDateTime = datetime.datetime.now() + datetime_offset
    cursor.execute(
        "UPDATE Session SET expDateTime = %s WHERE sessionID = %s;",
        (expDateTime, sessionID)
    )
    db.commit()

def delete_session(sessionID):
    cursor.execute(
        "DELETE FROM Session WHERE sessionID = %s;",
        (sessionID,)
    )
    db.commit()

def delete_expired_sessions():
    cursor.execute("SELECT username, sessionID, expDateTime FROM Session;")
    result = cursor.fetchall()
    for db_username, db_sessionID, db_expDateTime in result:
        if(db_expDateTime < datetime.datetime.now()):
            logging.info("deleting an expired session for \"" + db_username + "\"")
            delete_session(db_sessionID)

def test_session(username):
    expDateTimeSQL = "SELECT expDateTime FROM Session WHERE sessionID = %s;"

    sessionID = create_session(username)
    cursor.execute(expDateTimeSQL, (sessionID,))
    result = cursor.fetchall()
    logging.debug("sessionID: " + sessionID)
    logging.debug("expDateTime: " + str(result[0][0]))
    logging.debug("valid session? " + str(validate_session(username, sessionID)))

    update_session(sessionID, datetime.timedelta(days=2))
    cursor.execute(expDateTimeSQL, (sessionID,))
    result = cursor.fetchall()
    logging.debug("expDateTime: " + str(result[0][0]))
    logging.debug("valid session? " + str(validate_session(username, sessionID)))

    update_session(sessionID, datetime.timedelta(days=-5))
    cursor.execute(expDateTimeSQL, (sessionID,))
    result = cursor.fetchall()
    logging.debug("expDateTime: " + str(result[0][0]))
    logging.debug("valid session? " + str(validate_session(username, sessionID)))

    delete_session(sessionID)
    logging.debug("valid session? " + str(validate_session(username, sessionID)))

class DatabaseConnectionLostException(Exception):
    pass

class MissingHeaderException(Exception):
    pass

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

    def check_db_connection(self):
        ## try to reconnect
        if not db.is_connected():
            logging.error("Lost connection to database, reconnecting...")
            connect_to_db()
        ## connection was permanently lost
        if not db.is_connected():
            logging.error("Failed to reconnect.")
            self.send_response_only(500) ## Internal Server Error
            self.end_headers()
            raise DatabaseConnectionLostException

    ## still need to do something with this, preferably not compromise the entire system XD
    def do_GET(self):
        self.check_db_connection()

        self.send_response_only(200) ## OK
        self.end_headers()
        self.wfile.write(bytes(get_all_accounts(), encoding))

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
                return_success, error_message = add_user_account(
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
                    self.wfile.write(bytes(json_response, encoding))
                else:
                    self.send_response_only(403) ## Forbidden
                    self.end_headers()
                    json_response = json.dumps({
                        "errorMessage": error_message
                    })
                    self.wfile.write(bytes(json_response, encoding))
                return

            if(form.getvalue("action") == "Login"):
                if form.getvalue("passwordHash") == None:
                    raise MissingHeaderException
                if validate_credentials(form.getvalue("username"), form.getvalue("passwordHash")):
                    sessionID = create_session(form.getvalue("username"))
                    if sessionID != "":
                        self.send_response_only(200) ## OK
                        self.end_headers()
                        json_response = json.dumps({
                            "message": "successfully logged in",
                            "sessionID": sessionID
                        })
                        self.wfile.write(bytes(json_response, encoding))
                    else:
                        self.send_response_only(403) ## Forbidden
                        self.end_headers()
                        json_response = json.dumps({
                            "errorMessage": "\"" + form.getvalue("username") + "\" already has a session"
                        })
                        self.wfile.write(bytes(json_response, encoding))
                else:
                    self.send_response_only(401) ## Unauthorized
                    self.end_headers()
                    json_response = json.dumps({
                        "errorMessage": "valid credentials not provided"
                    })
                    self.wfile.write(bytes(json_response, encoding))
                return

            ## important security note: sessions are still vulnerable to forgery or replay attacks if not secured with TLS/SSL
            if validate_session(form.getvalue("username"), form.getvalue("sessionID")):
                if form.getvalue("sessionID") == None:
                    raise MissingHeaderException
                update_session(form.getvalue("sessionID"))
                ## put secured actions here
                if form.getvalue("action") == "Action":
                    self.send_response_only(200) ## OK
                    self.end_headers()
                    json_response = json.dumps({
                        "message": "test action"
                    })
                    self.wfile.write(bytes(json_response, encoding))
                elif form.getvalue("action") == "Logout":
                    delete_session(form.getvalue("sessionID"))
                    self.send_response_only(200) ## OK
                    self.end_headers()
                    json_response = json.dumps({
                        "message": "logged out"
                    })
                    self.wfile.write(bytes(json_response, encoding))
                elif form.getvalue("action") == "DeleteAccount":
                    if remove_user_account(form.getvalue("username")):
                        self.send_response_only(200) ## OK
                        self.end_headers()
                        json_response = json.dumps({
                            "message": "account deleted"
                        })
                        self.wfile.write(bytes(json_response, encoding))
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
                self.wfile.write(bytes(json_response, encoding))
            
        except MissingHeaderException:
            self.send_response_only(400) ## Bad Request
            self.end_headers()
            json_response = json.dumps({
                "errorMessage": "please include all required headers"
            })
            self.wfile.write(bytes(json_response, encoding))

def connect_to_db():
    try:
        global db, cursor
        db = mysql.connector.connect(
            host=db_address,
            user=db_username,
            password=db_password,
            database=db_name
        )
        cursor = db.cursor()
        logging.info("Connected to database.")
    except:
        logging.critical("Couldn't connect to database.")

## setup
logging.basicConfig(format='%(levelname)-8s: %(message)s', level=logging.DEBUG)
# logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)
connect_to_db()
if not db.is_connected():
    exit(-1)
delete_expired_sessions()

## test code
if run_tests_on_startup:
    test_username, test_password = "testaccount", "badpassword1"
    add_user_account(test_username, test_password, "John Doe")
    logging.debug("test account validated? " + str(validate_credentials(test_username, hashlib.sha256(test_password.encode(encoding)).hexdigest())))
    print()
    test_session(test_username)
    print()
    remove_user_account(test_username)

## run https server
try:
    httpd = ThreadingHTTPServer((server_address, server_port), SimpleHTTPRequestHandler)
    httpd.socket = ssl.wrap_socket(
        httpd.socket,
        keyfile=ssl_key_file,
        certfile=ssl_cert_file,
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
if cursor is not None:
    cursor.close()
if db is not None:
    db.close()
    logging.info("Closed database connection.")