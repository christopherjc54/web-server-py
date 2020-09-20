# Python Database Interface Server

HTTP/S interface for database access.

## GET Request ##
Any GET request will return a list of all usernames and passwords in the form they were initially sent to the server.

## POST Request form-data Keys ##
- action
  - see Actions
  - max size: 15 characters
- username
- [password]
  - only used for ```CreateUserSecure``` and ```CreateUserInsecure```
  - if using ```CreateUserSecure```, password should be pre-hashed with SHA-256
  - max size: 256 characters
- [passwordHash]
  - required for all actions except ```CreateUserSecure``` and ```CreateUserInsecure```
  - SHA-256 hash

## Actions ##
- ```CreateUserSecure```
  - uses pre-hashed SHA-256 password to add new account to database
  - POST form-data keys:
    - action
    - username
    - password
- ```CreateUserInsecure```
  - uses plain-text password to add new acount to database
  - POST form-data keys:
    - action
    - username
    - password
- ```Action``` 
  - test action to verify login validation works
  - POST form-data keys:
    - action
    - username
    - passwordHash