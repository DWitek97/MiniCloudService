## Documentation for setup

### Create database user with password
* Login to **mysql**:

```console
  sudo mysql
```
* Create a new user on localhost with password:
```console
  CREATE USER 'newuser'@'localhost' IDENTIFIED BY 'password';
```

```console
  GRANT ALL PRIVILEGES ON * . * TO 'newuser'@'localhost';
```
Replace "newuser" with desired username and "password" with desired password:

* Reload all the privileges to take effect:
```console
  FLUSH PRIVILEGES;
```

### Install mysql-server
```console
sudo apt install mysql-server
```

### Grant root privileges for user
```console
  visudo
  ```
* Enter the following under root user: "Dave ALL=(ALL:ALL)ALL"
* Save changes with **Ctrl-X**, **Y**, **Enter**

### Setup HTTPS

### Import database dump
```console
sudo mysql test_db < /home/Dave/TeamProject-SoSe21-TeamB/flask_server/Database.sql
```

### Credentials
For accessing database, see **db_config.yaml**
