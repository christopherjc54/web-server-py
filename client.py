#!/usr/bin/env python3

from getpass import getpass
import hashlib
import http.client
import ssl
import urllib.parse
import logging
import json

## config
server_address = "localhost"
server_port = 4443
ssl_cert_file = "ssl/cert.pem"

## session globals
username = ""
sessionID = ""

## globals
connection = None
commands = (
    "Login",
    "Logout",
    "CreateAccountSecure",
    "CreateAccountInsecure",
    "Action",
    "DeleteAccount",
    "help",
    "exit"
)
headers = {
    "Content-type": "application/x-www-form-urlencoded",
    "Accept": "text/plain"
}
encoding = "utf-8"

def print_help():
    print("Commands available:")
    for cmd in commands:
        print("  " + cmd)

## setup
logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)
try:
    ssl_context = ssl.create_default_context()
    ssl_context.load_verify_locations(ssl_cert_file)
    ssl_context.check_hostname = False
    connection = http.client.HTTPSConnection(server_address, server_port, context=ssl_context)
except ssl.SSLError as e:
    logging.error(e)
    logging.error("Failed to secure connection request.")
    exit(-1)
except http.client.HTTPException as e:
    logging.error(e)
    logging.error("Failed to connect to server.")
    exit(-1)

## run client
try:
    print_help()
    while True:
        print()
        input_cmd = input("Enter a command: ")
        print()

        for cmd in commands:
            if input_cmd.lower() == cmd.lower():
                if input_cmd != cmd:
                    input_cmd = cmd
                break
            
        if input_cmd == "Login":
            username = input("Enter username: ")
            passwordHash = hashlib.sha256(getpass("Enter password: ").encode(encoding)).hexdigest()
            params = urllib.parse.urlencode({
                "username": username,
                "passwordHash": passwordHash,
                "action": input_cmd
            })
            del passwordHash
            connection.request("POST", "", params, headers)
            del params
            response = connection.getresponse()
            try:
                json_response = json.loads(response.read().decode(encoding))
                if response.status == 200:
                    sessionID = json_response["sessionID"]
                    print(json_response["message"])
                    print("sessionID: " + sessionID)
                else:
                    logging.error(str(response.status) + " " + str(response.reason))
                    logging.error(json_response["errorMessage"])
            except:
                logging.error(str(response.status) + " " + str(response.reason))

        
        elif input_cmd == "Logout":
            params = urllib.parse.urlencode({
                "username": username,
                "sessionID": sessionID,
                "action": input_cmd
            })
            connection.request("POST", "", params, headers)
            response = connection.getresponse()
            try:
                json_response = json.loads(response.read().decode(encoding))
                if response.status == 200:
                    username = sessionID = ""
                    print(json_response["message"])
                else:
                    logging.error(str(response.status) + " " + str(response.reason))
                    logging.error(json_response["errorMessage"])
            except:
                logging.error(str(response.status) + " " + str(response.reason))
        
        elif input_cmd == "CreateAccountSecure" or input_cmd == "CreateAccountInsecure":
            is_secure = ("Insecure" not in input_cmd)
            username = input("Enter new username: ")
            while True:
                password = getpass("Enter new password: ")
                password_confirm = getpass("Confirm new password: ")
                if password == password_confirm:
                    del password_confirm
                    break
                else:
                    print("Passwords did not match, please try again.")
            display_name = input("Enter display name: ")
            if is_secure:
                password = hashlib.sha256(password.encode(encoding)).hexdigest()
            params = urllib.parse.urlencode({
                "username": username,
                "passwordHash" if is_secure else "password": password,
                "action": input_cmd,
                "displayName": display_name
            })
            del password ## minimize risk of password being stolen from memory
            connection.request("POST", "", params, headers)
            del params
            response = connection.getresponse()
            try:
                json_response = json.loads(response.read().decode(encoding))
                if response.status == 201: ## Created
                    print(json_response["message"])
                else:
                    logging.error(str(response.status) + " " + str(response.reason))
                    logging.error(json_response["errorMessage"])
            except:
                logging.error(str(response.status) + " " + str(response.reason))
        
        elif input_cmd == "Action":
            params = urllib.parse.urlencode({
                "username": username,
                "sessionID": sessionID,
                "action": input_cmd
            })
            connection.request("POST", "", params, headers)
            response = connection.getresponse()
            try:
                json_response = json.loads(response.read().decode(encoding))
                if response.status == 200:
                    print(json_response["message"])
                else:
                    logging.error(str(response.status) + " " + str(response.reason))
                    logging.error(json_response["errorMessage"])
            except:
                logging.error(str(response.status) + " " + str(response.reason))
        
        elif input_cmd == "DeleteAccount":
            params = urllib.parse.urlencode({
                "username": username,
                "sessionID": sessionID,
                "action": input_cmd
            })
            connection.request("POST", "", params, headers)
            response = connection.getresponse()
            try:
                json_response = json.loads(response.read().decode(encoding))
                if response.status == 200:
                    username = sessionID = ""
                    print(json_response["message"])
                else:
                    logging.error(str(response.status) + " " + str(response.reason))
                    logging.error(json_response["errorMessage"])
            except:
                logging.error(str(response.status) + " " + str(response.reason))

        elif input_cmd == "help":
            print_help()
        
        elif input_cmd == "exit":
            ## attempt to end current session in case server only allows one session per user
            if sessionID != "":
                params = urllib.parse.urlencode({
                    "username": username,
                    "sessionID": sessionID,
                    "action": "Logout"
                })
                connection.request("POST", "", params, headers)
                response = connection.getresponse()
                try:
                    json_response = json.loads(response.read().decode(encoding))
                    if response.status == 200:
                        print("Logging out...")
                    else:
                        raise Exception
                except:
                    logging.error(str(response.status) + " " + str(response.reason))
                    logging.error("Error logging out.")
            break
    
        else:
            print("Please enter a valid command.")

except KeyboardInterrupt:
    print() ## put bash shell's "^C" on its own line
except Exception as e:
    logging.critical(e)
## close socket safely
if connection is not None:
    connection.close()
    print("Server connection closed.")