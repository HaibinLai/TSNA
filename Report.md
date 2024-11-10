# TSNA- A Telnet like Service with simplified NTLM Authentication

**Author: Haibin Lai,** 
**Student ID: 12211612,**

## Structure

> Introduction
>
>Command Output
>>Task1
>>Task2
>>Task3
>>Task4
>>Task5
>
>Wireshark


---
## Introduction on Telnet

Telnet is a network protocol primarily used to establish text-based, bidirectional communication
 between a local computer and a remote server. It operates over a TCP/IP connection, allowing users to remotely control servers via command-line interface. Telnet is often used to manage devices, servers, or network equipment, but due to its lack of encryption, it poses security risks and has largely been replaced by encrypted protocols like SSH.


![Pasted image 20241109231955.png](png%2FPasted%20image%2020241109231955.png)

A figure showing how Telnet works on Client/Server


## Command Output

The following figure shows the output of each command in system.

### Task1: Connection Establishment

When we first start our sesrver, it starts a Thread TCP Server. It can handle multiple clients.
```python
if __name__ == '__main__':  
    server_address = host  
    server_port = port  
    # Create the server  
    with socketserver.ThreadingTCPServer((host, port), TSNAServerHandler) as server:  
        print("serving at host", server_address, "with port: ", server_port)  
        # Activate the server;  
        try:  
            server.serve_forever()  
        except KeyboardInterrupt:  
            print("Shutting down by keyboard")
```


The server will wait for TCP connection. It will listen for the specfic `host` and `port`. When the data is got, it will enter `main_loop` with `client_address` and `login_user`.
```python
class TSNAServerHandler(socketserver.BaseRequestHandler):  
    def handle(self):  
        print('Got connection from', self.client_address)  
        sc_socket = self.request  
        if sc_socket is not None:  
            sc_socket.send("success".encode('UTF-8'))  
        else:  
            print("Fail to catch a socket")  
        login_user = ''  
        is_continue = True  
  
        # get data  
        while is_continue:  
            is_continue, login_user = (  
                main_loop(socket_conn=sc_socket, client_address=self.client_address, login_user=login_user))
```

Now the client can be able to send a ip:port to establish a TCP connection.

![Pasted image 20241109232509.png](png%2FPasted%20image%2020241109232509.png)

Next, on the `main_loop`, it will handle recv data and save it into `data_log.txt`.

![Pasted image 20241109232907.png](png%2FPasted%20image%2020241109232907.png)

![Pasted image 20241109232957.png](png%2FPasted%20image%2020241109232957.png)



### Task 2: User Authentication

At the beginning of initializing server, it will load user-password from `user_records_txt`.

```python
def load_users(user_records_txt):  
    """  
    Task 2.1 Load saved user information (username and password)    :param user_records_txt: a txt file containing username and password records    :return users: dict {'username':'password'}    """    # Done: finish the codes  
    users = {}  # Initialize  
  
    if not os.path.exists(user_records_txt):  
        file = open(user_records_txt, 'w')  
        file.close()  
  
    with open(user_records_txt, 'r') as user_r:  
        for line in user_r:  
            line = line.strip()  
            if line:  # Ensure the line is not empty  
                username, password = line.split(':', 1)  # Split  
                users[username] = password  # Store  
  
    return users
```


And client can register a new user with new password.
```python
def user_register(cmd, users):  
    """  
    Task 2.2 Register command processing    :param cmd: Instruction string    :param users: The dict to hold information about all users    :return feedback message: str    """    # done: finish the codes  
    new_username = cmd[1]  
    new_password = cmd[2]  
  
    # Attempt to register a user that is already registered  
    if new_username in users:  
        print("Username is already in users!")  
        return FAILURE("Username is already in users!")  
    users[new_username] = new_password  
    with open(user_inf_txt, 'a') as user_r:  
        user_r.write(new_username+":"+new_password+"\n")  
  
    return SUCCESS("Your Registered Username is " + new_username)
```

And it will be registered in server.

![Pasted image 20241109233319.png](png%2FPasted%20image%2020241109233319.png)


Both the data log and user file will not record the password in **plaintext** . Instead, they will be recorded as **Ciphertext**.

![Pasted image 20241109233444.png](png%2FPasted%20image%2020241109233444.png)

Now the user can login to its record.

![Pasted image 20241109233717.png](png%2FPasted%20image%2020241109233717.png)

The server side shows the logging procedure. We will explain this logs on NTLM Authentication.

![Pasted image 20241109233735.png](png%2FPasted%20image%2020241109233735.png)


## Task 3: NTLM Authentication

The procedure of NTLM authenrication as the assignment request is shown as following figure.

![Pasted image 20241109235959.png](png%2FPasted%20image%2020241109235959.png)

![Pasted image 20241110001526.png](png%2FPasted%20image%2020241110001526.png)

So, when first send the message, password will be encrypted in function `ntlm_hash_func` .

```python
def ntlm_hash_func(password):  
    """  
    This function is used to encrypt passwords by the MD5 algorithm    """    # 1. Convert password to hexadecimal format  
    hex_password = ''.join(format(ord(char), '02x') for char in password)  
  
    # 2. Unicode encoding of hexadecimal passwords  
    unicode_password = hex_password.encode('utf-16le')  
  
    # 3. The MD5 digest algorithm is used to Hash the Unicode encoded data  
    md5_hasher = hashlib.md5()  
    md5_hasher.update(unicode_password)  
  
    # Returns the MD5 Hash  
    return md5_hasher.hexdigest()
```

As the wireshark shows, it contains `user_name` HaibinLai in plain context and encrypted password.



Then, the server will determine if the password in MD5 are the same in Database MD5:
![Pasted image 20241110002232.png](png%2FPasted%20image%2020241110002232.png)
```python
def login_authentication(conn, cmd, users):  
    login_user = cmd[1]  
    login_password = cmd[2]  
    if login_user in users:  
        if users[login_user] == login_password:  
            challenge = generate_challenge()  # a challenge
            conn.send(challenge)  
  
            calcu = conn.recv(1024)  
            ans = calculate_response(login_password, challenge)  
            if ans == calcu:  
                print("Logged in successfully!")  
                return SUCCESS("login is successful"), login_user  
            else:  
                print("Authentication Failed!")  
                return FAILURE("Authentication Failed!"), None  
        else:  
            return FAILURE("Wrong password!"), None  
    else:  
        return FAILURE("The user does not exist!"), None
```


Next, both client and server will check the `HMAC-SHA256` encrypted code with encrypted password with 8 random byte sent by Server.
```python
def generate_challenge():  
    """  
    Task 3.2    :return information: bytes random bytes as challenge message    """    # done: finish the codes  
    random_bytes = os.urandom(8)  
    print("Random bytes for challenge: ", random_bytes)  
    return random_bytes
```

Here we find the 8 byte: `9c 0c 24 a6 ca af 4c 59` . (Here `\xafLY` means `4c 59` are `LY` in `ASCII`) . As for X11 in Wireshark, it's because it's it default detecting protocol.

![Pasted image 20241110002929.png](png%2FPasted%20image%2020241110002929.png)
![Pasted image 20241110004520.png](png%2FPasted%20image%2020241110004520.png)
![Pasted image 20241110004315.png](png%2FPasted%20image%2020241110004315.png)



After getting 8 byte challenge, both client and server encrypted with  `HMAC-SHA256`.

![Pasted image 20241110002305.png](png%2FPasted%20image%2020241110002305.png)

```python
def calculate_response(ntlm_hash: str, challenge: bytes):  
    # 假设 ntlm_hash 是一个字符串，使用 utf-8 编码转换为字节  
    ntlm_hash_bytes = ntlm_hash.encode('utf-8') if isinstance(ntlm_hash, str) else bytes(ntlm_hash)  
  
    # 假设 challenge 是字节串，直接使用  
    # 如果 challenge 也是字符串，需要转换为字节  
    challenge_bytes = challenge if isinstance(challenge, bytes) else challenge.encode('utf-8')  
    return hmac.new(ntlm_hash_bytes, msg=challenge_bytes, digestmod=hashlib.sha256).digest()
```


Then the encrypted code in client side will send to Server to check whether it pass the challenge.

![Pasted image 20241110002726.png](png%2FPasted%20image%2020241110002726.png)
![Pasted image 20241110002503.png](png%2FPasted%20image%2020241110002503.png)

If success, it will login.
![Pasted image 20241110002750.png](png%2FPasted%20image%2020241110002750.png)




### Task 4: Command Processing


`sum $(num1) $(num2) ...`
note that it's limited to `float` format.

![[Pasted image 20241110010548.png]]

`multiply $(num1) $(num2) ...`
![[Pasted image 20241110010706.png]]

`sub $(num1) $(num2)`

`subtract $(num1) $(num2)`

![[Pasted image 20241110011753.png]]

#### login logout help, changepwd
![[Pasted image 20241110013112.png]]

## Exception


### 1. TCP Connection

#### IP Address
**Not Allowed IP** : 
1. not in 32bits.(`inet_aton` convert an IP address in string format (123.45.67.89) to the 32-bit packed binary format used in low-level network functions.
`Invalid IP Port: ", server_port`

2. 0.0.0.0: it represents "all network interfaces" or "local address" but cannot be used to connect to a remote host.
`Invalid IP for 0.0.0.0, it represent all network interfaces.`

3. Invalid ip without correct form of "ip:port"
`Invalid IP and port format. Please use ip:port with ipv4 form: ", ip_p`

**Special Allowed IP**:
1. localhost


#### Connection Refused
`Connection fail!`

---

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

### Lack of input number
        if len(msg) == 1:
            return FAILURE("lack of number!"), login_user

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





Li, Y., Chard, R., Babuji, Y., Chard, K., Foster, I., & Li, Z. (2024). UniFaaS: Programming across distributed cyberinfrastructure with federated function serving (arXiv:2403.19257). https://arxiv.org/abs/2403.19257