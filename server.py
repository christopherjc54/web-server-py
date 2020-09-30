#!/usr/bin/env python3

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import ssl
import cgi
import mysql.connector
import random, string
import hashlib
import datetime

def add_user_account(username, original_password, plain_text=True):
    salt = ''.join(random.SystemRandom().choice(string.hexdigits) for _ in range(16))
    if plain_text:
        hashed_password = hashlib.sha256(original_password.encode()).hexdigest()
    else:
        hashed_password = original_password
    hash = hashlib.sha256(hashed_password.encode() + salt.encode()).hexdigest()
    try:
        cursor.execute(
            "INSERT INTO Account (username, passwordHash, salt, hash) VALUES (%s, %s, %s, %s);",
            (username, hashed_password, salt, hash)
        )
        db.commit() ## would need exception check and db.rollback() if one of many commits fail (ACID property)
    except mysql.connector.IntegrityError: ## used for duplicate key and foreign key constraint errors
        print("error: user \"" + username + "\" already exists")
        return False
    except mysql.connector.Error as e:
        print("Error Code: " + str(e.errno))
        print("SQL State: " + str(e.sqlstate))
        print("Message: " + e.msg)
        raise e

    print()
    print("Added new account to database:")
    print("  Username: " + username)
    print("  Password: " + original_password)
    if plain_text:
        print("  Hashed Password: " + hashed_password)
    print("  Salt: " + salt)
    print("  Hash: " + hash)
    print()

    return True

def remove_user_account(username):
    cursor.execute(
        "DELETE FROM Account WHERE username = %s;",
        (username,)
    )
    db.commit()

def get_all_accounts():
    cursor.execute("SELECT * FROM Account;")
    result = cursor.fetchall()
    if len(result) > 0:
        account_str = ""
        for username, password, salt, password_hash in result:
            if account_str != "":
                account_str += "\n"
            account_str += username + " " + password + " " + salt + " " + password_hash
        return account_str
    else:
        return "no accounts found"

def validate_login(username, password_hash):
    cursor.execute(
        "SELECT (username, salt, hash) FROM Account WHERE username = %s;",
        (username,)
    )
    result = cursor.fetchall()
    if len(result) > 0:
        for db_username, db_salt, db_hash in result:
            salted_hash = hashlib.sha256(password_hash.encode() + db_salt.encode()).hexdigest()
            if db_username == username and db_hash == salted_hash:
                return True
        print("error: \"" + username + "\" tried logging in with wrong password")
        return False
    else:
        print("error: \"" + username + "\" not found found when validating login")
        return False

def create_session(username, datetime_offset=datetime.timedelta(days=1, hours=0)):
    sessionID = ''.join(random.SystemRandom().choice(string.hexdigits) for _ in range(32))
    expDateTime = datetime.datetime.now() + datetime_offset
    cursor.execute(
        "INSERT INTO Session (username, sessionID, expDateTime) VALUES (%s, %s, %s);",
        (username, sessionID, expDateTime)
    )
    db.commit()
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
                print("deleting an expired session for \"" + username + "\"")
                delete_session(db_sessionID)
        print("error: all sessions for \"" + username + "\" expired")
    else:
        print("error: session not found")
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

def test_session(username):
    expDateTimeSQL = "SELECT expDateTime FROM Session WHERE sessionID = %s;"

    sessionID = create_session(username)
    cursor.execute(expDateTimeSQL, (sessionID,))
    result = cursor.fetchall()
    print("sessionID:", sessionID)
    print("expDateTime:", result)
    print("valid session?", validate_session(username, sessionID))

    update_session(sessionID, datetime.timedelta(days=2))
    cursor.execute(expDateTimeSQL, (sessionID,))
    result = cursor.fetchall()
    print("expDateTime:", result)
    print("valid session?", validate_session(username, sessionID))

    update_session(sessionID, datetime.timedelta(days=-5))
    cursor.execute(expDateTimeSQL, (sessionID,))
    result = cursor.fetchall()
    print("expDateTime:", result)
    print("valid session?", validate_session(username, sessionID))

    delete_session(sessionID)
    print("valid session?", validate_session(username, sessionID))

    print()
    input("Press any key to continue...")
    print()

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response_only(200)
        self.end_headers()
        self.wfile.write(bytes(get_all_accounts(), "utf-8"))

    def do_POST(self):
        form = cgi.FieldStorage(
            fp = self.rfile,
            headers = self.headers,
            environ = {
                'REQUEST_METHOD' : 'POST',
                'CONTENT_TYPE' : self.headers['Content-Type']
            }
        )

        if(form.getvalue("action") == "CreateAccountSecure" or form.getvalue("action") == "CreateAccountInsecure"):
            try:
                if add_user_account(
                    form.getvalue("username"),
                    form.getvalue("password"),
                    plain_text=("Insecure" in form.getvalue("action"))
                ):
                    self.send_response_only(200)
                    self.end_headers()
                    self.wfile.write(bytes("account succesfuly created", "utf-8"))
                else:
                    self.send_response_only(403) ## Forbidden
                    self.end_headers()
                    self.wfile.write(bytes("the user already exists", "utf-8"))
            except:
                ## database error occured
                self.send_response_only(400) ## Bad Request
                self.end_headers()
            return
        
        if validate_login(form.getvalue("username"), form.getvalue("passwordHash")):
            ## put secured actions here
            if form.getvalue("action") == "Action":
                self.send_response_only(200)
                self.end_headers()
                self.wfile.write(bytes("test action", "utf-8"))
            elif form.getvalue("action") == "DeleteAccount":
                remove_user_account(form.getvalue("username"))
                self.send_response_only(200)
                self.end_headers()
                self.wfile.write(bytes("account deleted", "utf-8"))
            else:
                self.send_response_only(400) ## Bad Request
                self.end_headers()
        else:
            self.send_response_only(401) ## Unauthorized
            self.end_headers()
            self.wfile.write(bytes("valid credentials not provided", "utf-8"))

def close_safely():
    httpd.server_close()
    print("Closed HTTP/HTTPS server.")
    cursor.close()
    db.close()
    print("Closed database connection.")

## connect to database
try:
    db = mysql.connector.connect(
        host="localhost",
        user="user",
        password="1234",
        database="DatabaseServer"
    )
    cursor = db.cursor()
    print("Connected to database.")
except:
    print("Couldn't connect to database.")
    exit(-1)

## test code
add_user_account("testaccount", "badpassword1")
test_session("testaccount")

## run http server
try:
    ## need to run with sudo to use port 443, otherwise use port 1024+
    httpd = ThreadingHTTPServer(("localhost", 4443), SimpleHTTPRequestHandler)
    httpd.socket = ssl.wrap_socket(
        httpd.socket,
        keyfile="private_key.pem",
        certfile="cert.pem",
        server_side=True
    )
    print("Waiting for HTTP/HTTPS requests...")
    httpd.serve_forever()
## make sure sockets and db close properly
except KeyboardInterrupt:
    print() ## put bash shell's "^C" on its own line
    close_safely()
except Exception as e:
    print(e)
    close_safely()