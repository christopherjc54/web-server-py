#!/bin/bash

# sudo apt install python3 python3-pip mysql-server openssl
# python3 -m pip install --upgrade pip setuptools cffi
# python3 -m pip install mysql-connector-python argon2-cffi pyseaweed requests

sudo service mysql start

# sudo mysql_secure_installation

# sudo mysql < sql/init_user.sql                                ## add user as root
mysql -u user --password=1234 < sql/init_db.sql                 ## create/clean database
mysql -u user --password=1234 < sql/init_app_messenger.sql      ## "messenger" app-specific db config

# openssl genrsa -out ssl/private_key.pem 2048
# openssl req -new -x509 -key ssl/private_key.pem -out ssl/cert.pem -days 365

python3 server

# sudo service mysql stop