#!/bin/bash

# this is the bash script we used for team project
# I copied it into "bonuspunkte.py", therefore this one is only for reference
# I deleted git repo path


# 1. Set variables for bash script commands
server_config_file_1="server {
    listen 80 default_server;
    server_name "
server_ip="$(curl -s http://checkip.amazonaws.com || printf "0.0.0.0")"
server_config_file_2=";
    return 301 https://\$host\$request_uri;
    }
    server {
        listen 443 ssl;
        server_name _;
        ssl_certificate /etc/nginx/ssl/nginx.crt;
        ssl_certificate_key /etc/nginx/ssl/nginx.key;
        location / {
            proxy_pass http://127.0.0.1:8000;
        }

        location /socket.io/ {
            proxy_pass              http://127.0.0.1:8000;
            proxy_redirect off;

            proxy_http_version      1.1;

            proxy_set_header        Upgrade                 "\$http_upgrade";
            proxy_set_header        Connection              "\"upgrade"\";

            proxy_set_header        Host                    "\$host";
            proxy_set_header        X-Real-IP               "\$remote_addr";
            proxy_set_header        X-Forwarded-For         "\$proxy_add_x_forwarded_for";
        }
}"
server_config="$server_config_file_1 $server_ip $server_config_file_2"

# 2. Update Linux apt:
sudo apt-get update
echo "update"

# 3. Install python3-pip package:
sudo apt-get install -y python3-pip
echo "pip3 installed"

# 4. Install flask:
pip3 install flask
echo "flask installed"

# 5. Install cryptography for encryption
pip3 install cryptography
echo "cryptography installed"

# 6. Install nginx server and gunicorn3:
sudo apt-get install -y nginx
sudo apt-get install -y gunicorn3
echo "nginx and gunicorn3 installed."

# pip install
pip3 install eventlet

# 7. Add private SSH Key
ssh_private_key="-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAyWqR8pKdpFza4+IaOAoPKDOCcLzQBZRQKqdaXE5DqbBl05nx
two4fdop+YAGBhI+mIU2VkQjhlh5ymDk5lUr+SkItRpPUDNheY52L4LejW3UqyJH
HzaHeXmknQqbXdEFjfRVzfGIYDFUo9zj8dyVcXqOMBLlu3SmIT3niQQnCJzK1fHI
4jyAh4l0MFDcOVYnj5+q5CxTk6ci8f8nxmXLzTzZfp/cZ3FgpN0xCr4cklvuWmY2
losEUSbTS6J7fNr2dAdY4yPGVMAPGwt2nM7Otsfg+mE5/AeuYAmos7Z62ey8kOIt
+7iZ8I3zkG0JqwDSDo5XDUmgji2OKKq0MeZyGQIDAQABAoIBAG/UNrJKyzHtyC6M
Y+hHVYEJkFvNyWW/of78qgPkBFdbtD2XFIh/KTxe+70mYrHOQWjnVXLyJBM8XmqJ
/60PDvoo2UfMEstBq9YUzfO1IqG9oD1gK8LdwLwmWMpEkFy3Z/EX/uf4ObLG0Oqm
Av1Pbr3xwK5aX6kDrBV6zGnbn1x8zKg5zEOR8HTg20fOou2bwYiTUjxibgqPMvN6
wjk3LUFVj8fU8sKyud6cZVARt+4z5/Y5BiXnf3KPEVbxhgC/7xfBHrrrGf3l3xZv
FwWix+IbkfePRX1T6R9U4FtDNlLdYYjoha4CBUJyx3OZxNdA/1MGTRrba/Q8vY+v
jBhiuHECgYEA8/f0ck/dk5xhuLHpFjJTxRioeKVd91yhhVRiSDfA9hFFmN6jTihB
0n+HjqiS7QpdNdI2VmxrfowegF7lmVk6rGXMBcRESduSLLL9VTlc2A8YfH9a3N7F
revd1vdIvS9cFZ9MY/IF02yi0maceG/XtmhsdfgDKFGTblXadJXbC10CgYEA01ln
HPg+PQo28vMlSkWFkwAJ9EWZAdZU5uZFLZhNACstTFYUq0qxQBW2wKr+IzLWtXpI
9ihv5oHRpuSkFWs6BcywDdBWTVJSwBs5/IR2zN10QHGlF0E6N6U6xZlPgyifL0LY
MWZAj0Fenh4pk7xOE0w1HQKdDLOqZhdCyaHO0e0CgYEAkEE58emVa7WY9puD5hMG
A1GsNAIbyKql+u9FWcxVtWnLDDQAvbMCEJRFtC2rCqwJJ0zPwlRDT0VMt7zk58Kh
9dQPSg2eD0ncab/AGYdchYiPgvXO5TB4FHmV54i6ItsBCOvzQFmX5kajE+OGe5Qu
KXYfQ7XNMCbkFOaA0FTXeyUCgYAWLxkqqkfmIk9YOvtcC2YU4vkogbGoxrWMsvjp
60WR0fZkP9jVjfaC8oSHPquESE7PJ7HG3MG6IUA/U1qBwQqLF0wXdxnH7e8vqOvy
PHk30brlFMiuYzNYKei8WvZEnxvuWwbUUJZQMx1aXXIhxq8vSV192QthDO7C3ogt
H+XUlQKBgCYIbtsXKzTyHsE9Ma9XQJqkqvc5WTzGhyqISChtlBZoGYpInyxiOUZ9
xNSYlAdSWaiyZ0VffCWXmnXbQd8bLjz2LBLgtH2v+sJpl2W5zDCrCmhu5x8RefA0
UcervOBwyZo7UL9IJJPI2Lz9mJrfNT9pG0zK72HEnTVLsCtpmdhx
-----END RSA PRIVATE KEY-----"

echo "$ssh_private_key" | sudo tee /root/.ssh/id_rsa_github
chmod 600 /root/.ssh/id_rsa_github
eval $(ssh-agent)
ssh-add /root/.ssh/id_rsa_github
echo "ssh private key successfully added"

# 8. Download/Copy GitHub Repo:
ssh-keyscan -H github.com >> /root/.ssh/known_hosts
# git clone repo
git clone git@github.com:Lizzylizard/WebAppBPCC.git ~/TeamProject-SoSe21-TeamB

# 9. Copy Server Config in Flaskapp config file
echo "$server_config" > /root/TeamProject-SoSe21-TeamB/flask_server/Flaskapp

# 10. Move Flaskapp config file to /etc/nginx/sites-enabled:
sudo mv /root/TeamProject-SoSe21-TeamB/flask_server/Flaskapp /etc/nginx/sites-enabled
echo "moved Folder"

# 11. Install libmysqlclient-dev for recursive requirement installation:
sudo apt-get install -y libmysqlclient-dev
echo "libmysqlclient installed"

# 12. Install all requirements for flask application from requirements.txt:
sudo pip3 install -r /root/TeamProject-SoSe21-TeamB/flask_server/requirements.txt
echo "requirements installed"

# 13. Install MySQL Workbench for database:
#sudo apt-get install -y mysql-workbench
#echo "mysql-workbench installed"

# 14. Install MySQL Server
sudo apt-get install -y mysql-server
echo "mysql-server installed"

# 15. Create DB user, set privileges, create database and import SQL dumpfile
sudo mysql <<EOF
CREATE USER 'admin'@'localhost' IDENTIFIED BY '#server12345!';
GRANT ALL PRIVILEGES ON *.* TO 'admin'@'localhost';
FLUSH PRIVILEGES;
CREATE database test_db;
EOF
sudo mysql test_db < /root/TeamProject-SoSe21-TeamB/flask_server/test_db.sql
echo "Database successfully created"

# 16. Edit length for ip addresses in nginx.conf
sudo sed -i '24i\server_names_hash_bucket_size 1024;' /etc/nginx/nginx.conf

# 17. create SSL certificte and move to nginx directory
sudo mkdir /etc/nginx/ssl
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/ssl/nginx.key -out /etc/nginx/ssl/nginx.crt -subj "/C=DE/ST=Hessen/L=Fulda/O=FuldaRealEstate/CN=www.FuldaRealEstate.de"
echo "SSL Certificate created"

# 18. delete default nginx config and replace with Flasapp config file
sudo rm /etc/nginx/sites-enabled/default
echo "default server config removed"

# 19. Restart nginx server:
sudo service nginx restart
echo "restart nginx"

# 20. Start server application via gunicorn3:
gunicorn3 --chdir /root/TeamProject-SoSe21-TeamB/flask_server/ application:application -w 1 -k eventlet --daemon
echo "start server"