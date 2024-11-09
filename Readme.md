# TSNA: A Telnet like Service with simplified NTLM Authentication
## Author: Haibin Lai, Student ID: 12211612

Project Repo: https://github.com/HaibinLai/TSNA.git

Telnet is a network protocol primarily used to establish text-based, bidirectional communication
 between a local computer and a remote server. It operates over a TCP/IP connection, allowing users
 to remotely control servers via command-line interface. Telnet is often used to manage devices,
 servers, or network equipment, but due to its lack of encryption, it poses security risks and has largely
 been replaced by encrypted protocols like SSH.

![img.png](png/Telnet.png)

### NTLM and User Authentication
#### Register an already registered user
return `FAILURE("Username is already in users!")`
```python
# Attempt to register a user that is already registered  
if new_username in users:  
    print("Username is already in users!")  
    return FAILURE("Username is already in users!")
```

Success case:
`SUCCESS("Your Registered Username is " + new_username)`


#### Login parameter less than 2
`FAILURE(Please re-enter the login command with your username and password)`

#### Login parameter more than 2
`FAILURE(Password shouldn't include spaces)`

#### Register parameter less than 2
`FAILURE(Please re-enter the command with username and password)`

#### Register parameterMore than 3
`FAILURE(Username or password shouldn't include spaces)`


#### Login after being logged in
`FAILURE("You have logged in "+login_user+", please logout before you want to change to other user")`, login_user
```python
elif msg[0] == 'login':  
    print("try to login at the same time!")  
    return FAILURE("You have logged in "+login_user+", please logout before you want to change to other user"), login_user
```

#### Register when logged in
return `FAILURE("The register command can only be done when not logging!")`, login_user

#### The user don't exist while log in
`FAILURE("The user does not exist!")`

#### The user's MD5 encrypt password doesn't match with DB log
`FAILURE("Wrong password!")`

#### Challenge failed
`FAILURE("Authentication Failed!")`


#### Register, changepwd, login with blanks
`Error on format!`
`FAILURE("Invalid password, please don't contain blank on password")`


#### Same Password
`FAILURE("Same password, please don't take same password!")`

---

### Telnet Service
#### More number in sub and divide
`return FAILURE("Please enter Valid number! subtract $(number1) $(number2) "), login_user`
`return FAILURE("Please enter Valid number! divide $(number1) $(number2) "), login_user`

#### Divide 0
return `FAILURE("The dividend cannot be zero!")`, login_user


#### Input NAN
`FAILURE("Please enter Valid number!")`

---

### Others
#### Exit with more parameters
return `FAILURE("What are you doing?")`, login_user

for example:
```
exit 1 DROP TABLE ALL
```


#### Disconnect
`200:disconnected`

A figure showing how Telnet works on Client/Server

Li, Y., Chard, R., Babuji, Y., Chard, K., Foster, I., & Li, Z. (2024). UniFaaS: Programming across distributed cyberinfrastructure with federated function serving (arXiv:2403.19257). https://arxiv.org/abs/2403.19257