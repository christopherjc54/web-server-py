# Python HTTPS API for Database Server

The purpose of this project is to create a fully functional interface for secure networked application development.

A sample client is provided to test functionality.

## GET Request ##
Any GET request will return a list of all usernames and passwords in the form they were initially sent to the server. This will change.

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
  - password should be pre-hashed with SHA3-512
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
  - uses pre-hashed SHA3-512 password to add new account to database
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