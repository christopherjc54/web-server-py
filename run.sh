#!/bin/bash

# sudo apt install python3 python3-pip mysql-server
# python3 -m pip install mysql-connector-python

sudo service mysql start

# sudo mysql_secure_installation

# sudo mysql < init_user.sql                      ## add user as root
mysql -u user --password=1234 < init_db.sql       ## create/clean database
# mysql -u user --password=1234 < init_data.sql   ## add sample data if needed

# openssl genrsa -out private_key.pem 2048
# openssl req -new -x509 -key private_key.pem -out cert.pem -days 360

python3 server.py

sudo service mysql stop