# ---------------------------------------------------
# Example for Server w/ socket SSL communication 
# ---------------------------------------------------
import socket
import ssl
from file_checksum import calculate_sha256_checksum

# Server configurations
HOST = '127.0.0.1'
PORT = 443
CERT_FILE = 'ssl_includes/server.crt'
KEY_FILE = 'ssl_includes/server.key'

# Default Messages
ATTESTATION_RQST = 'bootup_attestation'

# FPGA Bitstream Location
FPGA_BITSTREAM_FILE = 'lstm_app'

# Create a socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # Keep the server connection open
    # while True:

    # TODO: Check if this works
    # Use this to prevent "OSError: [Errno 98] Address already in use"
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

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

    secure_client_socket = ssl_context.wrap_socket(
        client_socket, 
        server_side=True,
        do_handshake_on_connect=True,
    )

    # Receive and print the message from the client
    data_received = secure_client_socket.recv(1024)
    data_received_utf8 = data_received.decode('utf-8')
    print("Received from client: {}".format(data_received_utf8))

    # Check if we received request for Attestation
    if data_received_utf8 == ATTESTATION_RQST:
        print("Attestation Request from client!")

        # Calculate FPGA Bitstream Checksum
        checksum = calculate_sha256_checksum(FPGA_BITSTREAM_FILE)

        # Get key result from FPGA
        puf = "pufdummyresult123"

        # Send to the client the calculated bitstream
        secure_client_socket.sendall(checksum.encode('utf-8'))

    else:
        print("Wrong request!")

    # Close the connection
    # secure_client_socket.close()

# except Exception as e:
#     print(e)

except KeyboardInterrupt:
    print("Server terminated by user.")

finally:
    server_socket.close()