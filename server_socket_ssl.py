# ---------------------------------------------------
# Example for Server w/ socket SSL communication 
# ---------------------------------------------------
import socket
import ssl

# Server configurations
HOST = '127.0.0.1'
PORT = 443
CERT_FILE = 'ssl_includes/server.crt'
KEY_FILE = 'ssl_includes/server.key'

# Create a socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # Bind the socket to a specific address and port
    server_socket.bind((HOST, PORT))

    # Listen for incoming connections
    server_socket.listen()

    print("--------------------------------------------------------")
    print("Edge Accelerator Bootup Attestation Server ")
    print("Server listening on {} [Port: {}]".format(HOST, PORT))
    print("--------------------------------------------------------")

    # Accept a client connection
    client_socket, client_address = server_socket.accept()

    # Wrap the socket with SSL/TLS
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    secure_client_socket = ssl_context.wrap_socket(client_socket, server_side=True)

    # Receive and print the message from the client
    data = secure_client_socket.recv(1024)
    print(f"Received from client: {data.decode('utf-8')}")

    # Send a response to the client
    response = "Hello, client! This is the server."
    secure_client_socket.sendall(response.encode('utf-8'))

    # Close the connection
    secure_client_socket.close()

except Exception as e:
    print(e)

finally:
    server_socket.close()