import socketserver
import time

from functions import *

commands = [
    '?',
    'help',
    'exit',
    'login {name} {password}',
    'register {name} {password}'
]

### Task 2.1 Read user information files
users = load_users(user_inf_txt)
print("users and their passwords")
print(users)


## Task 2.1

def main_loop(socket_conn: socket, client_address, login_user):
    """

    :param socket_conn: socket connection
    :param client_address: client IP address
    :param login_user: str current logged-in user
    :return continue flag: boolean for main loop continue judgement, login user: str
    """
    ## Task 1.3
    # TODO: finish the codes

    receive_data = ''
    try:
        receive_data = socket_conn.recv(1024).decode('utf-8')
    except ConnectionAbortedError:
        print("Connection aborted from "+client_address)
        return False, None

    print("Received data:", receive_data, " from ", client_address)
    data_log = str(client_address)
    with open("data_log.txt", 'a') as file:
        file.write(data_log+","+str(receive_data)+","+str(time.time())+"\n")
    file.close()
    ## Task 1.3

    # Command processing before login
    if not login_user:
        # Command processing without arguments
        if receive_data == '?' or receive_data == 'help' or receive_data == 'ls':
            feedback_data = 'Available commends: \n\t' + '\n\t'.join(commands)
            feedback_data = SUCCESS(feedback_data)
        elif receive_data == 'exit':
            feedback_data = 'disconnected'
            feedback_data = SUCCESS(feedback_data)
        else:
            # Command processing with arguments
            cmd = receive_data.split(' ')
            if cmd[0] == 'login':
                if len(cmd) < 3:
                    feedback_data = 'Please re-enter the login commend with your username and password'
                    feedback_data = FAILURE(feedback_data)
                elif len(cmd) == 3:
                    ## Task 2.3, 3.2, 3.5
                    feedback_data, login_user = login_authentication(socket_conn, cmd, users)
                    ## Task 2.3, 3.2, 3.5
                else:
                    feedback_data = "Password shouldn't include spaces"
                    feedback_data = FAILURE(feedback_data)
            elif cmd[0] == 'register':
                if len(cmd) < 3:
                    feedback_data = 'Please re-enter the command with username and password'
                    feedback_data = FAILURE(feedback_data)
                elif len(cmd) > 3:
                    feedback_data = "Username or password shouldn't include spaces"
                    feedback_data = FAILURE(feedback_data)
                else:
                    ## Task 2.2
                    feedback_data = user_register(cmd, users)
                    ## Task 2.2
            else:
                feedback_data = "Invalid command"
                feedback_data = FAILURE(feedback_data)
    else:
        ## Task 4
        feedback_data, login_user = login_cmds(receive_data, users, login_user)
        ## Task 4

    try:
        socket_conn.sendall(feedback_data.encode('UTF-8'))
        if feedback_data == '200:disconnected':
            return False, None
    except ConnectionResetError:
        print("close connection with", client_address)
        socket_conn.close()
        return False, None

    return True, login_user


## Task 1.2
## Connection establishment on server
# TODO: finish the codes
## Task 1.2
# https://docs.python.org/zh-cn/3.10/library/socketserver.html


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

# 127.0.0.1:6016
