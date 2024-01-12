# ---------------------------------------------------
# Example for Client w/ socket SSL communication 
# ---------------------------------------------------
# Creator   : Ilias Papalamprou
# Date      : 12/2023
# ---------------------------------------------------
import socket
import ssl
import subprocess

# Server configurations
HOST = '147.102.37.120'
PORT = 6666

# Server Client secure connection files
cert_file = 'ssl_includes/client.crt'
key_file = 'ssl_includes/client.key'

# Default Messages
att_request = "attestation_rqst"

# Bitstream files
xclbin_file = "bitstream/lstm.xclbin"

# Calculate values required for remote attestation
def remote_attestation(input_file):
    # Calculate file checksum
    file_checksum = "e6c2022a87a5f67f12289b2c699fba03cfb849c3eed83d820ac858f950648428"

    # Extract file signature
    file_signature = "f8e2a7b1d6934c0f9dc5450e76a91b6e5e257db4c52e9f062d2464937d3a1c99"

    # Generate attestation report
    attestation_report = file_checksum + file_signature

    return attestation_report

# Main program function
def main():
    # Create a socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    try:
        client_socket.connect((HOST, PORT))

    # Print an error if the connection was unsuccessful
    except Exception as e:
        print("[Client] Connection error: {}".format(e))

    print("--------------------------------------------------------")
    print("Edge Accelerator connected to {} [Port: {}]".format(HOST, PORT))
    print("--------------------------------------------------------")

    # Wrap the socket with SSL/TLS
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    # Disabling hostname verification
    ssl_context.check_hostname = False  

    # Disabling certificate verification
    ssl_context.verify_mode = ssl.CERT_NONE  

    # Load client certificate and private key
    ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    secure_client_socket = ssl_context.wrap_socket(client_socket, server_hostname=HOST)

    # Receive and print the response from the server
    data_received = secure_client_socket.recv(1024)
    data_received_utf8 = data_received.decode('utf-8')

    # Perform remote attestation procedure if the correct request is received
    if data_received_utf8 == att_request:
        print("Initalizing Remote Attestation Protocol... [Received: {}]".format(data_received_utf8))

        # Remote attestation function
        attestation_report = remote_attestation(xclbin_file)

        # Send attestation report to the verification server
        print("Sending Attestation report to the Verification Server...")
        print(attestation_report)

        secure_client_socket.sendall(attestation_report.encode('utf-8'))

        print("Waiting for response...")

        data_received = secure_client_socket.recv(1024)
        data_received_utf8 = data_received.decode('utf-8')

        if data_received_utf8 == "fail":
            print("A bad guy tries to program the Accelerator x_x")
            secure_client_socket.close()

        elif data_received_utf8 == "pass":
            print("Einai filos mou. Loading the application to the accelerator...")
            
            # Load the .xclbin application to the FPGA
            subprocess.run(["xclbinutil", "--help"])
    else:
        print("[Error] - Received: {}".format(data_received_utf8))

        # Close the connection
        secure_client_socket.close()

if __name__ == "__main__":
    main()
