# Python Database Interface Server

## POST form-data ##
- action
- username
- [password]
  - only used for ```CreateUserSecure``` and ```CreateUserInsecure```
  - if using ```CreateUserSecure```, password should be pre-hashed with SHA-256
- [passwordHash]
  - required for all actions except ```CreateUserSecure``` and ```CreateUserInsecure```

## Actions ##
- ```CreateUserSecure```
  - uses pre-hashed SHA-256 password to add new account to database
- ```CreateUserInsecure```
  - uses plain-text password to add new acount to database
- ```Action``` 
  - test action to verify login validation works