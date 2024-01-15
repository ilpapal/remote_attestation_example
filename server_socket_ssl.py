# ---------------------------------------------------
# Example for Server w/ socket SSL communication 
# ---------------------------------------------------
# Creator   : Ilias Papalamprou
# Date      : 12/2023
# ---------------------------------------------------
import socket
import ssl

# Server configurations (PORT > 1024 doesn't require sudo access)
HOST = "147.102.37.120"
PORT = 6666

# Server Client secure connection files
cert_file = "ssl_includes/server.crt"
key_file = "ssl_includes/server.key"

# Files required for attestation
xclbin_file = "bitstream/bitstream.bin"
xclbin_key = "example_key_1"
xlcbin_cert = "bitstream/xclbin_cert.crt"

# Default Messages
att_request = "attestation_rqst"

# Reference values for verification
vrf_checksum = "1ce65761516fad64f7acd86a1309aae1bc274bdfa87a26a762eb673d9e811c7a"
vrf_signature = "f8e2a7b1d6934c0f9dc5450e76a91b6e5e257db4c52e9f062d2464937d3a1c99"

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
    print("Remote Attestation Server")
    print("Server listening on {} [Port: {}]".format(HOST, PORT))
    print("--------------------------------------------------------")

    # Accept a client connection
    client_socket, client_address = server_socket.accept()

    # Wrap the socket with SSL/TLS
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)

    secure_client_socket = ssl_context.wrap_socket(
        client_socket, 
        server_side=True,
        do_handshake_on_connect=True,
    )

    # Send remote attestation request after successful connection
    print("Sending Remote Attestation request...")
    secure_client_socket.sendall(att_request.encode('utf-8'))

    # Receive and print the message from the client
    data_received = secure_client_socket.recv(128)
    data_received_utf8 = data_received.decode('utf-8')

    # Extract the different variables from the attestation report
    parsed_received = {}

    parsed_received['checksum'] = data_received_utf8[0:64]
    parsed_received['certificate'] = data_received_utf8[64:128]

    # Print received attestation report
    print("Received attestation report")
    print("Checksum : {}".format(parsed_received['checksum']))
    print("Certificate : {}".format(parsed_received['certificate']))

    # Check if we received the correct values
    if (parsed_received['checksum'] != vrf_checksum) or (parsed_received['certificate'] != vrf_signature):
        print("A bad guy tries to upload his code :(")

        # Send message that the attestation failed
        att_status = "fail"
        secure_client_socket.sendall(att_status.encode('utf-8'))

    else:
        print("Designer einai filos mou :)")

        # Send message that the attestation completed successfuly
        att_status = "pass"
        secure_client_socket.sendall(att_status.encode('utf-8'))        

except KeyboardInterrupt:
    print("Server terminated by user.")

# finally:
#     server_socket.close()