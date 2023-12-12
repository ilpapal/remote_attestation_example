# ---------------------------------------------------
# Example code for file checksum calculation
# ---------------------------------------------------
# Includes
import hashlib

# ---------------------------------------------------
# File to calculate checksum for
input_file = "lstm_app"

# Function to Calculate SHA-256 checksum
def calculate_sha256_checksum(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        # Read the file in chunks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256.update(byte_block)
    return sha256.hexdigest()

# Print the SHA-256 checksum
# checksum = calculate_sha256_checksum(input_file)
# print("SHA256 Checksum : {}".format(checksum))
