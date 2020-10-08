#!/bin/bash

# sudo apt install python3 python3-pip mysql-server
# python3 -m pip install -U cffi pip setuptools
# python3 -m pip install mysql-connector-python
# python3 -m pip install argon2-cffi

sudo service mysql start

# sudo mysql_secure_installation

# sudo mysql < sql/init_user.sql                                ## add user as root
mysql -u user --password=1234 < sql/init_db.sql                 ## create/clean database
mysql -u user --password=1234 < sql/init_app_messenger.sql      ## "messenger" app-specific db config

# openssl genrsa -out ssl/private_key.pem 2048
# openssl req -new -x509 -key ssl/private_key.pem -out ssl/cert.pem -days 360

python3 server

# sudo service mysql stop