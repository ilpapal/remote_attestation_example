import socket
import ssl

# from tls_server import HOST as SERVER_HOST
# from tls_server import PORT as SERVER_PORT

HOST = "147.102.37.120"
PORT = 60000

SERVER_HOST = "147.102.37.120"
SERVER_PORT = 60000

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

client = ssl.wrap_socket(client, keyfile="ssl_includes/client.key", certfile="ssl_includes/client.crt")

if __name__ == "__main__":
    client.bind((HOST, PORT))
    client.connect((SERVER_HOST, SERVER_PORT))

    while True:
        from time import sleep

        client.send("Hello World!".encode("utf-8"))
        sleep(1)