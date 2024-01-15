# ---------------------------------------------------
# Example for Client w/ socket SSL communication 
# ---------------------------------------------------
# Creator   : Ilias Papalamprou
# Date      : 12/2023
# ---------------------------------------------------
import socket
import ssl
import subprocess
from file_checksum import calculate_sha256_checksum

# Server configurations
HOST = '147.102.37.120'
PORT = 6666

# Server Client secure connection files
cert_file = 'ssl_includes/client.crt'
key_file = 'ssl_includes/client.key'

# Default Messages
att_request = "attestation_rqst"

# Acceleartion files
exec_file = "app_files/hello_world"
xclbin_file = "app_files/vadd.xclbin"


# Auxiliary functions to extract command output data
def extract_line_before_exit(output):
    lines = output.split('\n')
    for i, line in enumerate(lines):
        if "Exiting" in line:
            # Return the line before the "Exiting" line
            return lines[i - 1] if i > 0 else None
    return None

def extract_first_element(line):
    # Split the line by space and return the first element
    elements = line.split()
    return elements[0] if elements else None



# Calculate values required for remote attestation
def remote_attestation(input_file):
    # Extract bitstream from the xclbin application into a seperate file
    subprocess.run(["xclbinutil", "--force", "--dump-section", "BITSTREAM:RAW:app_files/bitstream_extract.bit", "--input", input_file])

    # Calculate bitstream checksum
    file_checksum = calculate_sha256_checksum("app_files/bitstream_extract.bit")

    # Extract file signature
    # file_signature = "f8e2a7b1d6934c0f9dc5450e76a91b6e5e257db4c52e9f062d2464937d3a1c99"
    get_signature_command = ["xclbinutil", "--input", "app_files/vadd_signed.xclbin", "--get-signature"]
    # execCmd("signature_test", get_signature_command)

    proc = subprocess.Popen(get_signature_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, _ = proc.communicate()

    output_str = output.decode('ascii')

    # Extract the signature from the command output
    line_before_exit = extract_line_before_exit(output_str)

    if line_before_exit != None:
        file_signature = extract_first_element(line_before_exit)
        print("File Signature : {}".format(file_signature))
    else:
        print("[Error] Unable to get file signature")

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
            # subprocess.run(["xclbinutil", "--help"])
    else:
        print("[Error] - Received: {}".format(data_received_utf8))

        # Close the connection
        secure_client_socket.close()

if __name__ == "__main__":
    main()
