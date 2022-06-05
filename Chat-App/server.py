import socket
import select
import threading
import json
import time
import logging
import utils
# Ahmet Hakan Simsek 150117060
# Mucahit Tanacioglu 150115006

rsa_key_registry = {}

rsa_private_key_registry = {}

def generate_public_and_private_rsa_keys_for_user(username):
    private_key, public_key = utils.get_private_and_public_rsa_keys()
    rsa_key_registry[username] = public_key.export_key()
    rsa_private_key_registry[username] = private_key.export_key()
    return private_key, public_key

# Create and configure logger
logging.basicConfig(filename="server.log",
                    format='%(asctime)s %(message)s',
                    filemode='w')

# Creating an object
logger = logging.getLogger()
# Setting the threshold of logger to DEBUG
logger.setLevel(logging.DEBUG)

# variables ip and ports ,header specify character length 10^10 max char
HEADER_LENGTH = 10
IP = "127.0.0.1"
PORT = 1234
UDP_PORT = 12345

# private chat variables for keep track of partners
pm_que = {}
pm_partners = {}

# udp connection
user_udp_times = {}
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_socket.bind((IP, UDP_PORT))

online_users = []


# function called when user login
def init_connection(client_socket):
    try:
        username_header = client_socket.recv(HEADER_LENGTH)
        password_header = client_socket.recv(HEADER_LENGTH)

        username_length = int(username_header.decode("utf-8").strip())
        password_length = int(password_header.decode("utf-8").strip())

        username = client_socket.recv(username_length)
        password = client_socket.recv(password_length)
        return {"username": username.decode("utf-8"), "password": password.decode("utf-8")}
    except:
        return False


# function that receive message from clients and parse it
def receive_message(client_socket):
    try:
        username_header = client_socket.recv(HEADER_LENGTH)
        message_type_header = client_socket.recv(HEADER_LENGTH)
        message_header = client_socket.recv(HEADER_LENGTH)

        username_length = int(username_header.decode("utf-8").strip())
        message_type_length = int(message_type_header.decode("utf-8").strip())
        message_length = int(message_header.decode("utf-8").strip())

        username = client_socket.recv(username_length)
        message_type = client_socket.recv(message_type_length)
        message = client_socket.recv(message_length)

        if not len(message):
            return False

        return {"username": username, "message_type": message_type, "message": message,
                "headers": [username_header, message_type_header, message_header]}
    except:
        return False


# reading json file which used for user database
def read_json(filename='data.json'):
    with open(filename, 'r') as file:
        # First we load existing data into a dict.
        file_data = json.load(file)
    return file_data


# function for writing user info to json file
def write_json(new_data, filename='data.json'):
    with open(filename, 'r+') as file:
        # First we load existing data into a dict.
        file_data = json.load(file)
        # Join new_data with file_data inside emp_details
        file_data["client"].append(new_data)
        # Sets file's current position at offset.
        file.seek(0)
        # convert back to json.
        json.dump(file_data, file, indent=4)
    return file_data


# function checks received client information whether its in json file or not
def log_in(name, password):
    isFound = False
    with open('data.json', 'r') as file:
        file_data = json.load(file)
        for i in file_data['client']:
            if i.get("name") == name:
                isFound = True
                return i.get("password") == password, isFound

        return False, isFound


# create user structure for writing json file
def sign_up(name, password):
    y = {"name": name,
         "password": password
         }
    return write_json(y)


# write user to json file
def register_user(user):
    is_login_succesful = False
    isFound = True
    while (not is_login_succesful) and isFound:
        is_login_succesful, isFound = log_in(user["username"], user["password"])
        if not isFound:
            print(f"User with {user['username']} successfully registered.")
            logger.info(f"User with {user['username']} successfully registered.")
            sign_up(user["username"], user["password"])
            return True
        elif is_login_succesful:
            print(f"User with {user['username']} logged in.")
            logger.info(f"User with {user['username']} logged in.")
            return True

        logger.warning(f"Username: {user['username']} already taken or Wrong password")
        print(f"Username: {user['username']} already taken or Wrong password")
        return False


# check whether user available for pm
def check_pm_user(pm_to):
    for socket, usr in clients.items():
        if usr["username"] == pm_to and usr["chatgroup"] == "public":
            return socket
    return False


# user's udp client receiver
def user_respond():
    global user_udp_times
    while True:
        data, addr = udp_socket.recvfrom(1024)
        tme, usr = data.decode("utf-8").split("|")

        user_udp_times[usr] = float(tme)


# check whether user active for given second with udp
def check(second, username):
    global user_udp_times, online_users

    while True:
        time.sleep(second)
        if user_udp_times[username] < (time.time() - second):
            logger.critical(f"Could not receive any connection from USER: {username}  for {second} secs and he/she "
                            f"become offline!")
            print(f"Could not receive any connection from USER: {username}  for {second} secs and he/she "
                            f"become offline!")
            del user_udp_times[username]
            if username in online_users:
                online_users.remove(username)

            print("Online users:\n")
            print(online_users)

            return


# create udp thread for users
def udp_check_for_user(username):
    # create udp thread for every client
    check_thread = threading.Thread(target=check, args=([20, username]))
    client_thread = threading.Thread(target=user_respond, args=([]))
    check_thread.start()
    client_thread.start()
    check_thread.join()
    client_thread.join()


# function to handle login request
def handle_login(server_name, server_header, server_socket):
    client_socket, client_address = server_socket.accept()

    user = init_connection(client_socket)

    if user is False:
        return
    # user either enter wrong password or tried to register but username already taken
    if not register_user(user):
        message_type = "LOGINRES".encode("utf-8")
        message_type_header = f"{len(message_type) :< {HEADER_LENGTH}}".encode("utf-8")
        error = "Username already taken or Wrong password"

        err_header = f"{len(error) :< {HEADER_LENGTH}}".encode("utf-8")
        client_socket.send(
            server_header + message_type_header + err_header + server_name + message_type + error.encode(
                "utf-8"))
    # user successfully logged in or registered
    else:
        message_type = "LOGINRES".encode("utf-8")
        message_type_header = f"{len(message_type) :< {HEADER_LENGTH}}".encode("utf-8")
        msg_ = "Login success!"
        msg_header = f"{len(msg_) :< {HEADER_LENGTH}}".encode("utf-8")
        client_socket.send(
            server_header + message_type_header + msg_header + server_name + message_type + msg_.encode(
                "utf-8"))
        socket_list.append(client_socket)
        user["chatgroup"] = "public"
        clients[client_socket] = user

        global user_udp_times
        if not user['username'] in user_udp_times.keys():
            user_udp_times[user['username']] = time.time()
        online_users.append(user['username'])
        udp_client_base = threading.Thread(target=udp_check_for_user, args=([user['username']]))
        udp_client_base.start()

        logger.info(f"Accepted new connection from {client_address[0]}:{client_address[1]} username:{user['username']}")
    generate_public_and_private_rsa_keys_for_user(user['username'])
    print('Server {} > {}'.format(user['username'], rsa_key_registry))


# function to handle pm request
def handle_pm_request(message, notified_socket, server_header, server_name):
    pm_to = message["message"].decode("utf-8")
    pm_to_socket = check_pm_user(pm_to.split(" ")[1])
    # check whether user available for pm
    if pm_to_socket:
        pm_que[pm_to_socket] = notified_socket
        pm_que[notified_socket] = pm_to_socket

        message_ = f"The user {message['username'].decode('utf-8')} want to have private chat with you(Y/N)?".encode(
            "utf-8")
        message_header = f"{len(message_) :< {HEADER_LENGTH}}".encode("utf-8")

        message_type_header = f"{len('PMREQ') :< {HEADER_LENGTH}}".encode("utf-8")

        pm_to_socket.send(
            server_header + message_type_header + message_header + server_name + "PMREQ".encode(
                "utf-8") + message_)
        logger.info(
            f"User: {message['username'].decode('utf-8')} requested private chat with user: {pm_to.split(' ')[1]}")
        return
    # user not available for pm
    else:
        error = "User does not exist or offline or already having chat with another person"
        err_header = f"{len(error) :< {HEADER_LENGTH}}".encode("utf-8")
        message_type_header = f"{len('PMRES') :< {HEADER_LENGTH}}".encode("utf-8")
        notified_socket.send(
            server_header + message_type_header + err_header + 'SERVER'.encode(
                "utf-8") + "PMRES".encode("utf-8") + error.encode("utf-8"))
        return


# function to handle pm response
def handle_pm_response(message, notified_socket, server_header, server_name):
    # requested user accepted pm request
    if message["message"].decode("utf-8") == "ACCEPT":  # ACCEPT
        requested_user_socket = pm_que[notified_socket]
        del pm_que[notified_socket]
        del pm_que[requested_user_socket]

        pm_partners[requested_user_socket] = notified_socket
        pm_partners[notified_socket] = requested_user_socket

        clients[requested_user_socket]["chatgroup"] = "PM"
        clients[notified_socket]["chatgroup"] = "PM"

        message_body = f"The user: {message['username'].decode('utf-8')} whom you requested private chat had accept your request,you are moving private chat now!".encode(
            "utf-8")
        msg_header = f"{len(message_body) :< {HEADER_LENGTH}}".encode("utf-8")
        pm_partners[notified_socket].send(
            server_header + message['headers'][1] + msg_header + server_name + "PMRES".encode(
                "utf-8") + message_body)
        logger.info(
            f"The PM start between {clients[requested_user_socket]['username']} and {clients[notified_socket]['username']}")
        return
    # requested user rejected pm request
    else:  # REJECT
        requested_user_socket = pm_que[notified_socket]
        del pm_que[notified_socket]
        del pm_que[requested_user_socket]

        message_body = f"The user: {message['username'].decode('utf-8')} whom you requested private chat had rejected your request!".encode(
            "utf-8")
        msg_header = f"{len(message_body) :< {HEADER_LENGTH}}".encode("utf-8")
        requested_user_socket.send(
            server_header + message['headers'][1] + msg_header + server_name + "PMRES".encode(
                "utf-8") + message_body)
        return


def receive_connection(socket_list, clients, server_socket):
    server_name = "SERVER".encode("utf-8")
    server_header = f"{len(server_name) :< {HEADER_LENGTH}}".encode("utf-8")

    while True:
        read_sockets, _, exception_sockets = select.select(socket_list, [], socket_list)

        for notified_socket in read_sockets:
            # handle login request of client
            if notified_socket == server_socket:
                handle_login(server_name, server_header, server_socket)

                continue

            else:
                message = receive_message(notified_socket)
                # lost connection to user
                if message is False:
                    logger.warning(f"Lost connection from {clients[notified_socket]['username']}")
                    socket_list.remove(notified_socket)
                    del clients[notified_socket]
                    continue

                # user sends pm request
                if message["message_type"].decode("utf-8") == "PMREQ":
                    handle_pm_request(message, notified_socket, server_header, server_name)
                    continue
                # user responds pm request
                elif message["message_type"].decode("utf-8") == "PMRES":
                    handle_pm_response(message, notified_socket, server_header, server_name)
                    continue

                # user sends private chat
                elif message["message_type"].decode('utf-8') == "PM":
                    partner_socket = pm_partners[notified_socket]
                    partner_socket.send(
                        message['headers'][0] + message['headers'][1] + message['headers'][2] + message['username'] +
                        message['message_type'] + message['message'])
                    continue

                # user wants to leave private chat
                elif message["message_type"].decode('utf-8') == "PMEXIT":
                    partner_socket = pm_partners[notified_socket]
                    # notify partner that he/she left pm
                    partner_socket.send(
                        message['headers'][0] + message['headers'][1] + message['headers'][2] + message['username'] +
                        message['message_type'] + message['message'])
                    # delete entry for these 2 partner

                    del pm_partners[notified_socket]
                    del pm_partners[partner_socket]
                    clients[notified_socket]['chatgroup'] = "public"
                    clients[partner_socket]['chatgroup'] = "public"
                    logger.info(
                        f"PM between users {message['username'].decode('utf-8')} and {clients[partner_socket]['username']} closed.")
                    print(
                        f"PM between users {message['username'].decode('utf-8')} and {clients[partner_socket]['username']} closed.")
                    continue
                # user sends message to public chat
                elif message["message_type"].decode('utf-8') == "CHAT":
                    for client_socket_iter in clients:
                        if client_socket_iter != notified_socket and (not client_socket_iter in pm_partners):
                            client_socket_iter.send(
                                message['headers'][0] + message['headers'][1] + message['headers'][2] + message[
                                    'username'] + message['message_type'] + message['message'])
                # user wants to leave program
                elif message["message_type"].decode('utf-8') == "LOGOUT":
                    message_type = "CLOSE".encode("utf-8")
                    message_type_header = f"{len(message_type) :< {HEADER_LENGTH}}".encode("utf-8")

                    msg_ = "Close client sockets".encode("utf-8")
                    msg_header = f"{len(message) :< {HEADER_LENGTH}}".encode("utf-8")
                    notified_socket.send(
                        server_header + message_type_header + msg_header + server_name + message_type + msg_)
                    logger.info(f"Closed connection from {clients[notified_socket]['username']}")
                    print(f"Closed connection from {clients[notified_socket]['username']}")
                    continue

                logger.info(
                    f"Received message from {message['username'].decode('utf-8')}: {message['message'].decode('utf-8')}")
                print(
                    f"Received message from {message['username'].decode('utf-8')}: {message['message'].decode('utf-8')}")

        for notified_socket in exception_sockets:
            socket_list.remove(notified_socket)
            del clients[notified_socket]


if __name__ == '__main__':

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((socket.gethostname(), PORT))

    server_socket.listen()

    socket_list = [server_socket]

    clients = {}

    thread = threading.Thread(target=receive_connection, args=([socket_list, clients, server_socket]))
    thread.start()
