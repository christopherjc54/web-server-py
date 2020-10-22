# Python HTTPS API Server

The purpose of this project is to create a fully functional interface for secured network application development.

A sample client is provided to test functionality.

## GET Request ##
Any GET request will return a printout of all usernames and display names. This will change.

## POST Request form-data Keys ##
- action
  - see Actions
- username
  - max size: 15 characters
- [password]
  - only used for ```CreateUserInsecure```
  - max size: 256 characters
- [passwordHash]
  - required for ```CreateUserSecure``` and ```Login```
  - password should be pre-hashed with SHA-512
- [sessionID]
  - required for all actions except ```CreateUserInsecure```, ```CreateUserSecure```, and ```Login```

## Actions ##
- ```Login```
  - validates credentials and logs in user with new session ID
  - POST form-data keys:
    - action
    - username
    - passwordHash
  - Non-Standard JSON Response
    - sessionID
- ```Logout```
  - logs out user by deleting current session ID
  - POST form-data keys:
    - action
    - username
    - sessionID
- ```CreateUserSecure```
  - uses pre-hashed SHA-512 password to add new account to database
  - POST form-data keys:
    - action
    - username
    - passwordHash
- ```CreateUserInsecure```
  - uses plain-text password to add new account to database
  - POST form-data keys:
    - action
    - username
    - password
- ```Action``` 
  - test action to verify login validation works
  - POST form-data keys:
    - action
    - username
    - sessionID
- ```DeleteAccount```
  - deletes account that's already been authenticated
  - POST form-data keys
    - action
    - username
    - sessionID

## Standard JSON Responses ##
- on success:
  - [message]
- on failure:
  - [errorMessage]

## Messenger POST Request form-data Keys
- [messageID]
  - required for ```SendMessage```, ```GetMessages```, ```MarkAsRead```, and ```DeleteMessage```
- [recipients]
  - required for ```SendMessage```
  - JSON list of usernames
- [messageContent]
  - required for ```SendMessage```
  - max size: 500 characters
- [uploadedFiles]
  - required for ```SendMessage```
  - JSON list of file names
  - should correlate with fileContent
- [fileContent]
  - required for ```SendMessage```
  - JSON dictionary of file names and base64-encoded file content
- [getOneMessage]
  - required for ```GetMessages```
  - "true"/"1" or "false"/"0"
- [getOnlyNewMessages]
  - required for ```GetMessages```
  - "true"/"1" or "false"/"0"
- [getFileContent]
  - required for ```GetMessages```
  - "true"/"1" or "false"/"0"
  - fileContent will be null if false
- [messageRead]
  - required for ```MarkAsRead```
  - "true"/"1" or "false"/"0"
- [mailboxType]
  - required for ```DeleteMessage```
  - "Inbox" or "Sent"

## Messenger Actions ##
- ```Action```
  - test action to verify custom app loading works
  - POST form-data keys:
    - action
    - username
    - sessionID
- ```SendMessage```
  - sends a message with zero to many file attachments to one or more recipients
  - POST form-data keys:
    - action
    - username
    - sessionID
    - recipients
    - messageContent
    - uploadedFiles
    - fileContent
  - Non-Standard JSON Response
    - messageID
- ```GetMessages```
  - retrieves one message, all unread messages, or all messages with optional file attachment download
  - POST form-data keys:
    - action
    - username
    - sessionID
    - getFileContent
    - getOneMessage
    - [messageID]
      - include if getOneMessage is true
    - [getOnlyNewMessages]
      - include if getOneMessage if false
  - Non-Standard JSON Response
    - messages => JSON list of message dictionaries
      - messageID
      - fromUsername
      - messageContent
      - sentDateTime
      - messageRead
      - fileList => JSON list of file dictionaries
        - fileID
        - fileName
        - fileContent
          - base64-encoded file content
- ```MarkAsRead```
  - Marks a message as read or unread.
  - POST form-data keys:
    - action
    - username
    - sessionID
    - messageID
    - messageRead
- ```DeleteMessage```
  - Deletes a message from specified mailbox.
  - POST form-data keys:
    - action
    - username
    - sessionID
    - messageID
    - mailboxType