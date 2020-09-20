#!/usr/bin/env python3

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import ssl
import cgi
import mysql.connector
import random, string
import hashlib

def add_user_account(username, original_password, plain_text=True):
    ## check for existing user first
    cursor.execute(
        "select * from Account where username = %s",
        (username,)
    )
    if len(cursor.fetchall()) > 0:
        return False

    salt = ''.join(random.SystemRandom().choice(string.hexdigits) for _ in range(16))
    if plain_text:
        hashed_password = hashlib.sha256(original_password.encode()).hexdigest()
    else:
        hashed_password = original_password
    hash = hashlib.sha256(hashed_password.encode() + salt.encode()).hexdigest()
    cursor.execute(
        "insert into Account values (%s, %s, %s, %s);",
        (username, hashed_password, salt, hash)
    )
    db.commit()
    ## would need exception check and db.rollback() if one of many commits fail (ACID property)

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

def get_all_accounts():
    cursor.execute("select * from Account;")
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
        "select `username`, `salt`, `hash` from Account where username = %s;",
        (username,)
    )
    result = cursor.fetchall()
    if len(result) > 0:
        for db_username, db_salt, db_hash in result:
            salted_hash = hashlib.sha256(password_hash.encode() + db_salt.encode()).hexdigest()
            if db_username == username and db_hash == salted_hash:
                return True
        return False
    else:
        return False

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
            return
        
        if validate_login(form.getvalue("username"), form.getvalue("passwordHash")):
            ## put secured actions here
            if form.getvalue("action") == "Action":
                self.send_response_only(200)
                self.end_headers()
                self.wfile.write(bytes("test action", "utf-8"))
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

## test functions here
add_user_account("secure", "leedle") ## test account

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