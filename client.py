#!/usr/bin/env python3

import getpass
import hashlib
import logging
import json

import requests

## config
server_address = "localhost"
server_port = 4443
ssl_enabled = False
ssl_cert_file = "ssl/cert.pem"

## session globals
username = ""
sessionID = ""

## globals
commands = (
    "Login",
    "Logout",
    "CreateAccountSecure",
    "CreateAccountInsecure",
    "Action",
    "DeleteAccount",
    "SendMessage",
    "help",
    "exit"
)
encoding = "utf-8"
server_url = "http" + ("s" if ssl_enabled else "") + "://" + server_address + ":" + str(server_port)

def print_help():
    print("Commands available:")
    for cmd in commands:
        print("  " + cmd)

## setup
logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)
logging.getLogger("urllib3").setLevel(logging.WARNING) ## suppress "requests" module's logging

def prompt_yes_no(prompt):
    while True:
        response = input(prompt + " yes/no: ")
        if response in ("yes", "y"):
            return True
        elif response in ("no", "n"):
            return False
        else:
            print("Sorry, please enter \"yes\" or \"no\"")

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
            passwordHash = hashlib.sha512(getpass.getpass("Enter password: ").encode(encoding)).hexdigest()
            response = requests.post(
                url=server_url,
                data={
                    "username": username,
                    "passwordHash": passwordHash,
                    "action": input_cmd
                },
                cert=(ssl_cert_file if ssl_enabled else None)
            )
            try:
                json_response = json.loads(response.content.decode(encoding))
                if response.status_code < 300:
                    sessionID = json_response["sessionID"]
                    print(json_response["message"])
                    print("sessionID: " + sessionID)
                else:
                    logging.error(str(response.status_code) + " " + str(response.reason))
                    logging.error(json_response["errorMessage"])
            except:
                logging.error(str(response.status_code) + " " + str(response.reason))
        
        elif input_cmd == "Logout":
            response = requests.post(
                url=server_url,
                data={
                    "username": username,
                    "sessionID": sessionID,
                    "action": input_cmd
                },
                cert=(ssl_cert_file if ssl_enabled else None)
            )
            try:
                json_response = json.loads(response.content.decode(encoding))
                if response.status_code < 300:
                    sessionID = ""
                    print(json_response["message"])
                else:
                    logging.error(str(response.status_code) + " " + str(response.reason))
                    logging.error(json_response["errorMessage"])
            except:
                logging.error(str(response.status_code) + " " + str(response.reason))
        
        elif input_cmd == "CreateAccountSecure" or input_cmd == "CreateAccountInsecure":
            is_secure = ("Insecure" not in input_cmd)
            new_username = input("Enter new username: ")
            while True:
                password = getpass.getpass("Enter new password: ")
                password_confirm = getpass.getpass("Confirm new password: ")
                if password == password_confirm:
                    del password_confirm
                    break
                else:
                    print("Passwords did not match, please try again.")
            display_name = input("Enter display name: ")
            if is_secure:
                password = hashlib.sha512(password.encode(encoding)).hexdigest()

            response = requests.post(
                url=server_url,
                data={
                    "username": new_username,
                    "passwordHash" if is_secure else "password": password,
                    "action": input_cmd,
                    "displayName": display_name
                },
                cert=(ssl_cert_file if ssl_enabled else None)
            )
            try:
                json_response = json.loads(response.content.decode(encoding))
                if response.status_code < 300:
                    print(json_response["message"])
                else:
                    logging.error(str(response.status_code) + " " + str(response.reason))
                    logging.error(json_response["errorMessage"])
            except:
                logging.error(str(response.status_code) + " " + str(response.reason))
        
        elif input_cmd == "Action":
            response = requests.post(
                url=server_url,
                data={
                    "username": username,
                    "sessionID": sessionID,
                    "action": input_cmd
                },
                cert=(ssl_cert_file if ssl_enabled else None)
            )
            try:
                json_response = json.loads(response.content.decode(encoding))
                if response.status_code < 300:
                    print(json_response["message"])
                else:
                    logging.error(str(response.status_code) + " " + str(response.reason))
                    logging.error(json_response["errorMessage"])
            except:
                logging.error(str(response.status_code) + " " + str(response.reason))
        
        elif input_cmd == "DeleteAccount":
            response = requests.post(
                url=server_url,
                data={
                    "username": username,
                    "sessionID": sessionID,
                    "action": input_cmd
                },
                cert=(ssl_cert_file if ssl_enabled else None)
            )
            try:
                json_response = json.loads(response.content.decode(encoding))
                if response.status_code < 300:
                    username = ""
                    sessionID = ""
                    print(json_response["message"])
                else:
                    logging.error(str(response.status_code) + " " + str(response.reason))
                    logging.error(json_response["errorMessage"])
            except:
                logging.error(str(response.status_code) + " " + str(response.reason))

        elif input_cmd == "SendMessage":
            recipient = input("Enter recipient's username: ")
            message_content = input("Enter message: ")
            upload_file = prompt_yes_no("Do you want to upload a file?")
            file_list = list()
            files = dict()
            if upload_file:
                while True:
                    file_name = input("Enter file name: ")
                    file_list.append(file_name)
                    files.update({ "files/" + file_name : open(file_name, "rb") })
                    if not prompt_yes_no("Do you want to upload another file?"):
                        break
            response = requests.post(
                url=server_url,
                data={
                    "username": username,
                    "sessionID": sessionID,
                    "action": input_cmd,
                    "recipient": recipient,
                    "messageContent": message_content,
                    "uploadedFiles": str(file_list)
                },
                files=files,
                cert=(ssl_cert_file if ssl_enabled else None)
            )
            try:
                json_response = json.loads(response.content.decode(encoding))
                if response.status_code < 300:
                    print(json_response["message"])
                else:
                    logging.error(str(response.status_code) + " " + str(response.reason))
                    logging.error(json_response["errorMessage"])
            except:
                logging.error(str(response.status_code) + " " + str(response.reason))

        elif input_cmd == "help":
            print_help()
        
        elif input_cmd == "exit":
            ## attempt to end current session in case server only allows one session per user
            if sessionID != "":
                if prompt_yes_no("Do you want to log out?"):
                    response = requests.post(
                        url=server_url,
                        data={
                            "username": username,
                            "sessionID": sessionID,
                            "action": "Logout"
                        },
                        cert=(ssl_cert_file if ssl_enabled else None)
                    )
                    try:
                        json_response = json.loads(response.content.decode(encoding))
                        if response.status_code < 300:
                            print("Logged out.")
                        else:
                            raise Exception
                    except:
                        logging.error(str(response.status_code) + " " + str(response.reason))
                        logging.error("Error logging out.")
            break
    
        else:
            print("Please enter a valid command.")

except KeyboardInterrupt:
    print() ## put bash shell's "^C" on its own line