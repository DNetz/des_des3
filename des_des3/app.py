import argparse, os, time
from Crypto.Cipher import DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def encrypt_or_decrypt_data(cipher, text, mode='encrypt'):
    """Encrypt or decrypt the given data using the cipher and mode entered by user input"""
    # Generate an Initialization Vector (IV) based on the block size of the cipher
    iv = get_random_bytes(cipher.block_size)
    if mode == 'encrypt':
        # Pad the data to make sure its length is a multiple of the block size
        padded_data = pad(text, cipher.block_size)
        # Encrypt the padded data and prepend the IV for decryption use
        encrypted_data = iv + cipher.encrypt(padded_data)
        return encrypted_data
    elif mode == 'decrypt':
        # Extract the IV from the beginning of the ciphertext
        iv = text[:cipher.block_size]
        # Decrypt the data and unpad it to get the original plaintext
        decrypted_data = unpad(cipher.decrypt(text[cipher.block_size:]), cipher.block_size)
        return decrypted_data



def handle_file_encryption_or_decryption(input_file_path, output_file_path, algo, mode):
    """Process a file for encryption or decryption, writing the result to another file."""

    # Generate a key of a length based on the encryption algorithm selected by user input
    encryption_key = get_random_bytes(8 if algo == 'DES' else 24)   
    # Initialize the encryption cipher based on the user's choice
    cipher_class = DES if algo == 'DES' else DES3
    cipher = cipher_class.new(encryption_key, cipher_class.MODE_CBC)

    try:
        # Open and read the input file in binary mode
        with open(input_file_path, 'rb') as input_file:
            data_to_process = input_file.read()

        # Process the data based on the chosen operation mode (encrypt or decrypt)
        if mode == 'encrypt':
            processed_data = encrypt_or_decrypt_data(cipher, data_to_process, 'encrypt')
        else:  # Decrypt
            processed_data = encrypt_or_decrypt_data(cipher, data_to_process, 'decrypt')

        # Write the ciphertext to the output file
        with open(output_file_path, 'wb') as output_file:
            output_file.write(processed_data)
        
        # if file does not exist, sleep for 1 second until it does exist:
        while not os.path.exists(output_file_path):
            time.sleep(1)

        print(f"File {mode}ed successfully. Output saved to {output_file_path}.")
    
    except IOError as e:
        # Handle errors related to file operations
        print(f"File operation error: {e}")
    except ValueError as e:
        # Handle errors related to the decryption process
          print(f"Decryption error (possible incorrect key or corrupted file): {e}")


def main():
    # Define and parse the command-line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--algo", choices=['DES', 'DES3'], help="Select either DES or DES3 for the encryption algorithm", required=True)
    parser.add_argument("--mode", choices=['encrypt', 'decrypt'], help="Choose the operation: encrypt or decrypt", required=True)
    parser.add_argument("--infile", type=str, help="Path to the input file", required=True)
    parser.add_argument("--outfile", type=str, help="Path to save the output file", required=True)
    args = parser.parse_args()

    # Execute the file processing based on user inputs
    handle_file_encryption_or_decryption(args.infile, args.outfile, args.algo, args.mode)

if __name__ == "__main__":
    main()