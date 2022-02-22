import socket
import time
import errno
import sys
import threading
# Mucahit Tanacioglu 150115006
# Ahmet Hakan Simsek 150117060

HEADER_LENGTH = 10

IP = "127.0.0.1"
PORT = 1234

IS_PM = False


# function to send general message
def send_message(client_socket, username):
    global IS_PM
    while True:
        message = input(f"{username} > ")
        message_type = "CHAT"
        if message:
            # user want to pm someone
            if message.split(" ")[0] == "@PM":
                message_type = "PMREQ"
            # user want to leave program
            elif message == "LOGOUT":
                message_type = "LOGOUT"
            # user want to exit pm
            elif IS_PM:
                if message == "EXIT PM":
                    message_type = "PMEXIT"
                    IS_PM = False
                else:
                    message_type = "PM"
            # if user trying to accept or reject pm request ignore this thread
            elif message == "Y" or message == "y" or message == "N" or message == "n":
                continue
            message = message.encode("utf-8")
            username_header = f"{len(username):< {HEADER_LENGTH}}".encode("utf-8")
            message_header = f"{len(message) :< {HEADER_LENGTH}}".encode("utf-8")
            message_type_header = f"{len(message_type) :< {HEADER_LENGTH}}".encode("utf-8")

            # send message to server
            client_socket.send(
                username_header + message_type_header + message_header + username.encode("utf-8") + message_type.encode(
                    "utf-8") + message)


# function for responding specific message type other than sending normal message
def send_simple_message(username, type, message):
    message = message.encode("utf-8")
    username_header = f"{len(username):< {HEADER_LENGTH}}".encode("utf-8")
    message_header = f"{len(message) :< {HEADER_LENGTH}}".encode("utf-8")
    message_type_header = f"{len(type) :< {HEADER_LENGTH}}".encode("utf-8")

    client_socket.send(
        username_header + message_type_header + message_header + username.encode("utf-8") + type.encode(
            "utf-8") + message)


# function that receiving messages from server
def receive_messaege(client_socket, my_username):
    global IS_PM
    while True:
        try:
            while True:
                # get message from server if server is up
                username_header = client_socket.recv(HEADER_LENGTH)
                if not len(username_header):
                    print("connection closed by the server")
                    sys.exit()

                # parse message
                username_length = int(username_header.decode("utf-8").strip())
                message_type_header = client_socket.recv(HEADER_LENGTH)
                message_type_length = int(message_type_header.decode("utf-8").strip())
                message_header = client_socket.recv(HEADER_LENGTH)
                message_length = int(message_header.decode("utf-8").strip())

                username = client_socket.recv(username_length).decode("utf-8")
                message_type = client_socket.recv(message_type_length).decode("utf-8")
                message = client_socket.recv(message_length).decode("utf-8")

                ## classify message types and take action accordingly

                # handle login respond message type
                if message_type == "LOGINRES":
                    return message
                # handle pm request message type
                elif message_type == "PMREQ":
                    respond_ = input(f"{message} > ")

                    if respond_ == "Y" or respond_ == "y":
                        send_simple_message(my_username, "PMRES", "ACCEPT")
                        global IS_PM
                        IS_PM = True
                    else:
                        send_simple_message(my_username, "PMRES", "REJECT")
                # handle pm respond message type
                elif message_type == "PMRES":
                    if " accept " in message:
                        IS_PM = True

                    print(message)
                # handle private message type
                elif message_type == "PM":
                    print(f"{username} > {message}")
                # handle user want to exit private chat
                elif message_type == "PMEXIT":
                    print(f"Your partner {username} left pm!")
                    IS_PM = False
                # handle logout
                elif message_type == "CLOSE":
                    print("Connection closed success!")
                    sys.exit()
                # public chat message
                else:
                    print(f"{username} > {message}")

        except IOError as e:
            if e.errno != errno.EAGAIN and e.errno != errno.WSAEWOULDBLOCK:
                print("Reading error", str(e))
                sys.exit()
            continue

        except Exception as e:
            print("General error", str(e))
            sys.exit()
            pass


# udp connection for checking periodically whether user online or not
def udp_check(sec, udp_socket, username):
    while True:
        udp_socket.sendto(str(time.time()).encode("utf-8") + str("|" + username).encode("utf-8"), (IP, 12345))
        time.sleep(sec)


if __name__ == '__main__':
    # keep looping until user succesfully login
    while True:
        my_username = input("Username: ")
        my_password = input("Password: ")

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        client_socket.connect((socket.gethostname(), PORT))
        client_socket.setblocking(False)

        username = my_username.encode("utf-8")
        password = my_password.encode("utf-8")
        username_header = f"{len(username):< {HEADER_LENGTH}}".encode("utf-8")
        password_header = f"{len(password):< {HEADER_LENGTH}}".encode("utf-8")

        # send user information for login
        client_socket.send(username_header + password_header + username + password)

        # receive server respond for login request
        login_respond = receive_messaege(client_socket, my_username)

        if login_respond == "Login success!":
            print("Login success!")
            break
        else:
            print(login_respond)

    # after user successfully logged in create udp socket and connect to server's udp socket for user online check
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_check_thread = threading.Thread(target=udp_check, args=([6, udp_socket, my_username]))
    udp_check_thread.start()

    # create tcp connection with server for chatting
    connect_thread = threading.Thread(target=send_message, args=([client_socket, my_username]))
    send_thread = threading.Thread(target=receive_messaege, args=([client_socket, my_username]))
    connect_thread.start()
    send_thread.start()
    connect_thread.join()
    send_thread.join()
