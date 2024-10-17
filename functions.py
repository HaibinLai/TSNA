import hmac
import os
import socket
import hashlib
import re
import random
import ast
import fileinput

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
        if int(server_port) > 65536 or int(server_port) <= 0:
            print("Invalid IP Port")
            return None, ValueError
    except ValueError:
        print("Invalid IP")
        return None, ValueError
    socket_client = socket.socket()
    socket_client.connect((str(server_ip), int(server_port)))
    info = socket_client.recv(1024)
    # socket_client.send("hello".encode('utf-8'))
    return socket_client, info
    

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
    # TODO: finish the codes


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
    # TODO: finish the codes


def server_message_encrypt(message):
    """
    Task 3.1 Determine whether the command is "login", "register", or "changepwd",
    If so, it encrypts the password in the command and returns the encrypted message and Password
    Otherwise, the original message and None are returned
    :param message: str message sent to server:
    :return encrypted message: str, encrypted password: str
    """
    # TODO: finish the codes
    

def generate_challenge():
    """
    Task 3.2
    :return information: bytes random bytes as challenge message
    """
    # TODO: finish the codes


def calculate_response(ntlm_hash, challenge):
    """
    Task 3.3
    :param ntlm_hash: str encrypted password
    :param challenge: bytes random bytes as challenge message
    :return expected response
    """
    # TODO: finish the codes
    

def server_response(server, password_hash):
    """
    Task 3.4 Receives the server response and determines whether the message returned by the server is an authentication challenge.
    If it is, the challenge will be authenticated with the encrypted password, and the authentication information will be returned to the server to obtain the login result
    Otherwise, the original message is returned
    :param server: socket server
    :param password_hash: encrypted password
    :return server response: str
    """
    # TODO: finish the codes


def login_cmds(receive_data, users, login_user):
    """
    Task 4 Command processing after login
    :param receive_data: Received user commands
    :param users: The dict to hold information about all users
    :param login_user: The logged-in user
    :return feedback message: str, login user: str
    """
    # TODO: finish the codes
    