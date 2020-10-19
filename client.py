#!/usr/bin/env python3

import getpass
import hashlib
import logging
import json
import os
import base64

import requests

## config
server_address = "localhost"
server_port = 4443
ssl_enabled = False
ssl_cert_file = "ssl/cert.pem"

## session globals
username = ""
sessionID = ""

## program globals
commands = (
    "Login",
    "Logout",
    "CreateAccountSecure",
    "CreateAccountInsecure",
    "Action",
    "DeleteAccount",
    "SendMessage",
    "GetMessages",
    "DeleteMessage",
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
            recipient_list = list()
            while True:
                recipient_list.append(input("Enter recipient's username: "))
                if not prompt_yes_no("Do you want to send message to someone else?"):
                    break
            message_content = input("Enter message: ")
            upload_file = prompt_yes_no("Do you want to upload a file?")
            file_list = list()
            file_content = dict()
            if upload_file:
                while True:
                    file_name = input("Enter file name: ")
                    file_list.append(file_name)
                    file_content.update({ file_name : str(base64.b64encode(open(file_name, "rb").read()), encoding=encoding) })
                    if not prompt_yes_no("Do you want to upload another file?"):
                        break
            response = requests.post(
                url=server_url,
                data={
                    "username": username,
                    "sessionID": sessionID,
                    "action": input_cmd,
                    "recipients": json.dumps(recipient_list),
                    "messageContent": message_content,
                    "uploadedFiles": json.dumps(file_list),
                    "fileContent": json.dumps(file_content)
                },
                cert=(ssl_cert_file if ssl_enabled else None)
            )
            try:
                json_response = json.loads(response.content.decode(encoding))
                if response.status_code < 300:
                    print(json_response["message"])
                    print("messageID: " + str(json_response["messageID"]))
                else:
                    logging.error(str(response.status_code) + " " + str(response.reason))
                    logging.error(json_response["errorMessage"])
            except:
                logging.error(str(response.status_code) + " " + str(response.reason))

        elif input_cmd == "GetMessages":
            get_one_message = not prompt_yes_no("Do you want to get all messages?")
            message_id = None
            get_only_new_message = None
            if get_one_message:
                message_id = input("Please enter the ID of the message you want: ")
            else:
                get_only_new_message = prompt_yes_no("Do you want to get only unread messages?")
            get_file_content = prompt_yes_no("Do you want to also download attached files?")
            response = requests.post(
                url=server_url,
                data={
                    "username": username,
                    "sessionID": sessionID,
                    "action": input_cmd,
                    "getOneMessage": str(get_one_message),
                    "messageID": message_id,
                    "getOnlyNewMessages" : str(get_only_new_message),
                    "getFileContent": str(get_file_content)
                },
                cert=(ssl_cert_file if ssl_enabled else None)
            )
            try:
                json_response = json.loads(response.content.decode(encoding))
                if response.status_code < 300:
                    print(json_response["message"])
                    # print("RAW Response:")
                    # print(json.dumps(json_response, indent=3))
                    folder_name = "message_attachments"
                    if get_file_content:
                        try:
                            os.mkdir(folder_name)
                        except FileExistsError:
                            pass
                    for response_message in json_response["messages"]:
                        print()
                        print("ID: " + str(response_message["messageID"]))
                        print("From: " + response_message["fromUsername"])
                        print("Sent: " + response_message["sentDateTime"])
                        attached_files = ""
                        if get_file_content:
                            try:
                                os.mkdir(folder_name + "/" + str(str(response_message["messageID"])))
                            except FileExistsError:
                                pass
                        for index, (response_file) in enumerate(response_message["fileList"]):
                            attached_files += response_file["fileName"]
                            if index < len(response_message["fileList"]) - 1:
                                attached_files += ", "
                            if get_file_content:
                                try:
                                    f = open(folder_name + "/" + str(response_message["messageID"]) + "/" + response_file["fileName"], "wb") ## use "xb" to prevent overwriting
                                    f.write(base64.b64decode(response_file["fileContent"]))
                                    f.close()
                                except FileExistsError:
                                    logging.error("\"" + response_file["fileName"] + "\" already exists.")
                        print("Files attached: " + ("none" if attached_files == "" else attached_files))
                        print("Message: " + response_message["messageContent"])
                        if response_message["messageRead"] == False:
                            print()
                            if prompt_yes_no("Do you want to mark this message as read?"):
                                while True:
                                    mark_as_read_response = requests.post(
                                        url=server_url,
                                        data={
                                            "username": username,
                                            "sessionID": sessionID,
                                            "action": "MarkAsRead",
                                            "messageID": response_message["messageID"],
                                            "messageRead": str(True)
                                        },
                                        cert=(ssl_cert_file if ssl_enabled else None)
                                    )
                                    if not mark_as_read_response.status_code < 300:
                                        print("Error marking as read.")
                                        if prompt_yes_no("Try again?"):
                                            continue
                                    break
                else:
                    logging.error(str(response.status_code) + " " + str(response.reason))
                    logging.error(json_response["errorMessage"])
            except json.JSONDecodeError:
                if response.status_code < 300:
                    print(str(response.status_code) + " " + str(response.reason))
                    print("Couldn't decode JSON.")
                else:
                    logging.error(str(response.status_code) + " " + str(response.reason))

        elif input_cmd == "DeleteMessage":
            message_id = input("Enter message ID: ")
            response = requests.post(
                url=server_url,
                data={
                    "username": username,
                    "sessionID": sessionID,
                    "action": input_cmd,
                    "mailboxType": "Inbox",
                    "messageID": message_id
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