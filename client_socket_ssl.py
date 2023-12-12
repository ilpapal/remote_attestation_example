# ---------------------------------------------------
# Example for Client w/ socket SSL communication 
# ---------------------------------------------------
import socket
import ssl

# Server configurations
# HOST = '127.0.0.1'
HOST = '127.0.0.1'
PORT = 443
CERT_FILE = 'ssl_includes/client.crt'
KEY_FILE = 'ssl_includes/client.key'

# Create a socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the server
client_socket.connect((HOST, PORT))

print("--------------------------------------------------------")
print("Client Connected to {} [Port: {}]".format(HOST, PORT))
print("--------------------------------------------------------")

# Wrap the socket with SSL/TLS
ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
ssl_context.check_hostname = False  # Disabling hostname verification
ssl_context.verify_mode = ssl.CERT_NONE  # Disabling certificate verification

# Load client certificate and private key
ssl_context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

secure_client_socket = ssl_context.wrap_socket(client_socket, server_hostname=HOST)

# Send a message to the server
message = "This is the correct nigger speaking"
secure_client_socket.sendall(message.encode('utf-8'))

# Receive and print the response from the server
data = secure_client_socket.recv(1024)
print(f"Received from server: {data.decode('utf-8')}")

# Close the connection
secure_client_socket.close()
