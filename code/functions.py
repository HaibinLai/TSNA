import hmac
import os
import socket
import hashlib
import re
import random
import ast
import fileinput
import decimal

host = "localhost"
port = 6016
user_inf_txt = 'users.txt'


login_commands = [
    '?',
    'help',
    'exit',
    'logout',
    'changepwd {newpassword}',
    'sum [a] [b] ...',
    'sub [a] [b]',
    'multiply [a] [b] ...',
    'divide [a] [b]'
]


def SUCCESS(message):
    """
    This function is designed to be easy to test, so do not modify it
    """
    return '200:' + message


def FAILURE(message):
    """
    This function is designed to be easy to test, so do not modify it
    """
    return '400:' + message


def ntlm_hash_func(password):
    """
    This function is used to encrypt passwords by the MD5 algorithm
    """
    # 1. Convert password to hexadecimal format
    hex_password = ''.join(format(ord(char), '02x') for char in password)

    # 2. Unicode encoding of hexadecimal passwords
    unicode_password = hex_password.encode('utf-16le')

    # 3. The MD5 digest algorithm is used to Hash the Unicode encoded data
    md5_hasher = hashlib.md5()
    md5_hasher.update(unicode_password)

    # Returns the MD5 Hash
    return md5_hasher.hexdigest()


def connection_establish(ip_p):
    """ Connect the host with IP:Port
    Task 1.1 Correctly separate the IP address from the port number in the string
    Returns the socket object of the connected server when the socket server address pointed to by IP:port is available
    Otherwise, an error message is given
    :param ip_p: str 'IP:port'
    :return socket_client: socket.socket() or None
    :return information: str 'success' or error information
    """
    # Done: finish the codes
    try:
        server_ip, server_port = ip_p.split(':')

        # port test
        if int(server_port) > 65536 or int(server_port) <= 0:
            print("Invalid IP Port: ", server_port)
            return None, "Please try again"

        # ip test
        if not is_valid_ipv4_socket(server_ip) and server_ip != 'localhost':
            print("Invalid IP")
            return None, "Please try again"
        if server_ip == '0.0.0.0':
            print("Invalid IP for 0.0.0.0, it represent all network interfaces.")

    except ValueError:
        print("Invalid IP and port format. Please use ip:port with ipv4 form: ", ip_p)
        return None, "Please try again"
    socket_client = socket.socket()
    try:
        socket_client.connect((str(server_ip), int(server_port)))
    except ConnectionRefusedError:
        print("Connection fail!")
    info = socket_client.recv(1024).decode('utf-8')
    # socket_client.send("hello".encode('utf-8'))
    return socket_client, info


def is_valid_ipv4_socket(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False
    

def load_users(user_records_txt):
    """
    Task 2.1 Load saved user information (username and password)
    :param user_records_txt: a txt file containing username and password records
    :return users: dict {'username':'password'}
    """
    # Done: finish the codes
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


def user_register(cmd, users):
    """
    Task 2.2 Register command processing
    :param cmd: Instruction string
    :param users: The dict to hold information about all users
    :return feedback message: str
    """
    # done: finish the codes
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


def login_authentication(conn, cmd, users):
    """
    Task 2.3 Login authentication
        You can simply use password comparison for authentication (Task 2.3 basic score)
        It can also be implemented according to the NTLM certification process to obtain Task 3.2 and 3.5 scores
    :param conn: socket connection to the client
    :param cmd: Instruction string
    :param users: The dict to hold information about all users
    :return: feedback message: str, login_user: str
    """
    # done: finish the codes
    login_user = cmd[1]
    login_password = cmd[2]
    if login_user in users:
        if users[login_user] == login_password:
            challenge = generate_challenge()
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


def server_message_encrypt(message: str):
    """
    Task 3.1 Determine whether the command is "login", "register", or "changepwd",
    If so, it encrypts the password in the command and returns the encrypted message and Password
    Otherwise, the original message and None are returned
    :param message: str message sent to server:
    :return encrypted message: str, encrypted password: str
    """
    # done: finish the codes
    code = message.split()

    if len(code) != 3 and code[0] != "changepwd":
        return message, None

    if code[0] == "login" or code[0] == "register":
        if len(code) == 3:
            print(code[0]+"ing")
            username = code[1]
            encrypted_message = ntlm_hash_func(code[2])
            return code[0]+" "+username+" "+encrypted_message, encrypted_message
        else:
            print("Error on format!")
            return message, None
    elif code[0] == "changepwd":
        if len(code) == 2:
            print(code[0] + "ing")
            encrypted_message = ntlm_hash_func(code[1])
            return code[0] + " " + encrypted_message, encrypted_message
        else:
            print("Error on format!")
            return message, None

    else:
        return message, None


def generate_challenge():
    """
    Task 3.2
    :return information: bytes random bytes as challenge message
    """
    # done: finish the codes
    random_bytes = os.urandom(8)
    print("Random bytes for challenge: ", random_bytes)
    return random_bytes


def calculate_response(ntlm_hash: str, challenge: bytes):
    """
    Task 3.3
    :param ntlm_hash: str encrypted password
    :param challenge: bytes random bytes as challenge message
    :return expected response
    """
    # done: finish the codes
    # 假设 ntlm_hash 是一个字符串，使用 utf-8 编码转换为字节
    # if ntlm_hash == None:

    ntlm_hash_bytes = ntlm_hash.encode('utf-8') if isinstance(ntlm_hash, str) else bytes(ntlm_hash)

    # 假设 challenge 是字节串，直接使用
    # 如果 challenge 也是字符串，需要转换为字节
    challenge_bytes = challenge if isinstance(challenge, bytes) else challenge.encode('utf-8')
    return hmac.new(ntlm_hash_bytes, msg=challenge_bytes, digestmod=hashlib.sha256).digest()


def server_response(server, password_hash):
    """
    Task 3.4 Receives the server response and determines whether the message
    returned by the server is an authentication challenge.
    If it is, the challenge will be authenticated with the encrypted password,
     and the authentication information will be returned to the server to obtain the login result

    Otherwise, the original message is returned
    :param server: socket server
    :param password_hash: encrypted password
    :return server response: str
    """
    # done: finish the codes
    message = server.recv(1024)
    # print(message)
    # print(len(message))
    if len(message) == 8:
        # for sum 1 2 3 4 5
        if message.startswith(b'200:') or message.startswith(b'400:') :
            return message
        else:
            print('Server challenge')
            cal_response = calculate_response(password_hash, bytes(message))
            server.sendall(cal_response)
            calcu = server.recv(1024)
            return calcu

    return message


def login_cmds(receive_data: str, users, login_user):
    """
    Task 4 Command processing after login
    :param receive_data: Received user commands
    :param users: The dict to hold information about all users
    :param login_user: The logged-in user
    :return feedback message: str, login user: str
    """
    # done: finish the codes

    msg = receive_data.split()
    if msg[0] == 'exit':
        if len(msg) == 1:
            return SUCCESS("disconnected"), login_user
        else:
            return FAILURE("What are you doing?"), login_user

    elif msg[0] == 'logout':
        if len(msg) == 1:
            print("Logging out")
            return SUCCESS("Logout from current user: " + login_user), None
        else:
            return FAILURE("What are you doing?"), login_user

    elif msg[0] == 'changepwd':
        print("Trying to change password")
        if len(msg) != 2:
            return FAILURE("Invalid password, please don't contain blank on password"), login_user
        new_pwd = msg[1]
        old_pwd = users[login_user]
        if new_pwd == old_pwd:
            return FAILURE("Same password, please don't take same password!"), login_user
        users[login_user] = new_pwd
        return SUCCESS("Successfully changed password"), login_user

    elif msg[0] == 'login':
        print("try to login at the same time!")
        return FAILURE("You have logged in "+login_user+", please logout before you want to change to other user"), login_user

    if msg[0] == 'sum':
        if len(msg) == 1:
            return FAILURE("lack of number!"), login_user
        try:
            numbers = [float(num) for num in msg[1:]]
            # print(numbers)
        except ValueError:
            return FAILURE("Please enter Valid number!"), login_user

        try:
            # 尝试将 msg 中的所有元素转换为 decimal.Decimal 类型
            numbers = [decimal.Decimal(num) for num in msg[1:]]
        except decimal.InvalidOperation:
            # 如果转换失败，返回错误信息
            return FAILURE("Please enter valid numbers!"), login_user
        sum_ = 0
        for num in numbers:
            sum_ += num

        return SUCCESS(str(sum_)), login_user

    elif msg[0] == 'multiply':
        if len(msg) == 1:
            return FAILURE("lack of number!"), login_user
        try:
            numbers = [float(num) for num in msg[1:]]
            # print(numbers)
        except ValueError:
            return FAILURE("Please enter Valid number!"), login_user

        try:
            # 尝试将 msg 中的所有元素转换为 decimal.Decimal 类型
            numbers = [decimal.Decimal(num) for num in msg[1:]]
        except decimal.InvalidOperation:
            # 如果转换失败，返回错误信息
            return FAILURE("Please enter valid numbers!"), login_user

        ans = 1
        for num in numbers:
            ans = ans * num
        return SUCCESS(str(ans)), login_user

    elif msg[0] == 'subtract' or msg[0] == 'sub':
        if len(msg) == 1:
            return FAILURE("lack of number!"), login_user
        if len(msg) != 3:
            return FAILURE("Please enter Valid number! subtract $(number1) $(number2) "), login_user
        try:
            numbers = [float(num) for num in msg[1:]]
        except ValueError:
            return FAILURE("Please enter Valid number!"), login_user

        try:
            # 尝试将 msg 中的所有元素转换为 decimal.Decimal 类型
            numbers = [decimal.Decimal(num) for num in msg[1:]]
        except decimal.InvalidOperation:
            # 如果转换失败，返回错误信息
            return FAILURE("Please enter valid numbers!"), login_user

        ans = numbers[0] - numbers[1]
        return SUCCESS(str(ans)), login_user

    elif msg[0] == 'divide':
        if len(msg) == 1:
            return FAILURE("lack of number!"), login_user
        if len(msg) != 3:
            return FAILURE("Please enter Valid number! divide $(number1) $(number2) "), login_user
        try:
            numbers = [float(num) for num in msg[1:]]
        except ValueError:
            return FAILURE("Please enter Valid number!"), login_user
        if numbers[1] == 0:
            return FAILURE("The dividend cannot be zero!"), login_user

        try:
            # 尝试将 msg 中的所有元素转换为 decimal.Decimal 类型
            numbers = [decimal.Decimal(num) for num in msg[1:]]
        except decimal.InvalidOperation:
            # 如果转换失败，返回错误信息
            return FAILURE("Please enter valid numbers!"), login_user

        ans = numbers[0] / numbers[1]
        return SUCCESS(str(ans)), login_user

    elif msg[0] == '?' or msg[0] == 'help' or msg[0] == 'ls':
        if len(msg) == 1:
            feedback_data = 'Available commands: \n\t' + '\n\t'.join(login_commands)
            return SUCCESS(feedback_data), login_user
        else:
            return FAILURE("What are you doing?"), login_user

    elif msg[0] == 'register':
        return FAILURE("The register command can only be done when not logging!"), login_user

    else:
        return FAILURE("Invalid command! Please use help to show commands!"), login_user

