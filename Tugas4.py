import os
import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# DES Core Functions

IP = (
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
)
IP_INV = (
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
)
E = (
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12,
    13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24,
    25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
)
S_BOX = (
    ((14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7), (0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8), (4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0), (15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13)),
    ((15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10), (3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5), (0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15), (13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9)),
    ((10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8), (13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1), (13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7), (1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12)),
    ((7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15), (13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9), (10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4), (3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14)),
    ((2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9), (14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6), (4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14), (11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3)),
    ((12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11), (10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8), (9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6), (4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13)),
    ((4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1), (13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6), (1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2), (6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12)),
    ((13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7), (1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2), (7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8), (2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11))
)
P = (
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
)
PC_1 = (
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51,
    43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7,
    62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
)
PC_2 = (
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33,
    48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
)
shifts_table = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)

def bytes_to_bits(data: bytes) -> list[int]:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

def bits_to_bytes(bits: list[int]) -> bytes:
    byte_list = []
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        byte_list.append(byte)
    return bytes(byte_list)

def bits_to_hex(bits: list[int]) -> str:
    hex_str = ""
    for i in range(0, len(bits), 4):
        nibble = 0
        for j in range(4):
            nibble = (nibble << 1) | bits[i + j]
        hex_str += f'{nibble:x}'
    return hex_str

def int_to_bits(n: int, length: int) -> list[int]:
    bits = [0] * length
    for i in range(length - 1, -1, -1):
        bits[i] = n & 1
        n >>= 1
    return bits

def xor_bits(a: list[int], b: list[int]) -> list[int]:
    return [x ^ y for x, y in zip(a, b)]

def permute(block: list[int], table: tuple[int]) -> list[int]:
    return [block[i - 1] for i in table]

def generate_round_keys(key_bits: list[int]) -> list[list[int]]:
    key = permute(key_bits, PC_1)
    C = key[:28]
    D = key[28:]

    round_keys = []
    for shift in shifts_table:
        C = C[shift:] + C[:shift]
        D = D[shift:] + D[:shift]
        combined_key = C + D
        round_keys.append(permute(combined_key, PC_2))
    return round_keys

def feistel_function(right: list[int], round_key: list[int]) -> list[int]:
    right_expanded = permute(right, E)
    xored = xor_bits(right_expanded, round_key)
    
    sbox_output = []
    for i in range(8):
        chunk = xored[i*6 : (i+1)*6]
        row = (chunk[0] << 1) | chunk[5]
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        val = S_BOX[i][row][col]
        val_bits = int_to_bits(val, 4)
        sbox_output.extend(val_bits)
    
    return permute(sbox_output, P)

def des_process_block(block_bits: list[int], round_keys: list[list[int]]) -> list[int]:
    permuted_block = permute(block_bits, IP)
    left = permuted_block[:32]
    right = permuted_block[32:]

    for i in range(16):
        new_right = xor_bits(left, feistel_function(right, round_keys[i]))
        left = right
        right = new_right

    final_block_data = right + left
    return permute(final_block_data, IP_INV)

def add_padding(data: bytes) -> bytes:
    block_size = 8
    padding_len = block_size - (len(data) % block_size)
    padding_byte = bytes([padding_len])
    return data + padding_byte * padding_len

def remove_padding(data: bytes) -> bytes:
    if not data:
        return b""
    padding_len = data[-1]
    if padding_len < 1 or padding_len > 8:
        return data
    return data[:-padding_len]

def des_encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    padded_plaintext = add_padding(plaintext)
    key_bits = bytes_to_bits(key)
    iv_bits = bytes_to_bits(iv)
    round_keys = generate_round_keys(key_bits)
    ciphertext = b""
    previous_cipher_block = iv_bits
    for i in range(0, len(padded_plaintext), 8):
        block_bytes = padded_plaintext[i:i+8]
        block_bits = bytes_to_bits(block_bytes)
        block_to_encrypt = xor_bits(block_bits, previous_cipher_block)
        encrypted_block = des_process_block(block_to_encrypt, round_keys)
        ciphertext += bits_to_bytes(encrypted_block)
        previous_cipher_block = encrypted_block
    return ciphertext

def des_decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    key_bits = bytes_to_bits(key)
    iv_bits = bytes_to_bits(iv)
    round_keys = generate_round_keys(key_bits)
    round_keys.reverse()
    plaintext = b""
    previous_cipher_block = iv_bits
    for i in range(0, len(ciphertext), 8):
        block_bytes = ciphertext[i:i+8]
        block_bits = bytes_to_bits(block_bytes)
        decrypted_block_intermediate = des_process_block(block_bits, round_keys)
        plaintext_block = xor_bits(decrypted_block_intermediate, previous_cipher_block)
        plaintext += bits_to_bytes(plaintext_block)
        previous_cipher_block = block_bits
    return remove_padding(plaintext)

# Network and Chat Functions

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

# New RSA Functions for manual signing

def raw_rsa_sign(data_bytes, private_key):
    m = int.from_bytes(data_bytes, byteorder='big')
    s = pow(m, private_key.d, private_key.n)
    return s.to_bytes(256, byteorder='big')

def raw_rsa_verify(data_bytes, signature_bytes, public_key):
    m = int.from_bytes(data_bytes, byteorder='big')
    s = int.from_bytes(signature_bytes, byteorder='big')
    m_check = pow(s, public_key.e, public_key.n)
    return m == m_check

def receive_messages(connection, key, iv):
    while True:
        try:
            data = connection.recv(2048)
            if not data:
                print("\n[Connection Lost]")
                break
            
            print(f"\r <- Ciphertext (Hex) Received: {data.hex()}")

            decrypted_bytes = des_decrypt_cbc(data, key, iv)
            message = decrypted_bytes.decode('latin-1')
            
            print(f"Message Received: {message}")
            print("Enter Message (or 'exit'): ", end="", flush=True)

        except ConnectionResetError:
            print("\n[Connection Lost]")
            break
        except Exception as e:
            print(f"\n[Data Receiving Error: {e}]")
            print("Enter Message (or 'exit'): ", end="", flush=True)

def chat_loop(connection, key, iv):
    try:
        receiver_thread = threading.Thread(
            target=receive_messages, 
            args=(connection, key, iv), 
            daemon=True
        )
        receiver_thread.start()

        while True:
            message_to_send = input("Enter Message (or 'exit'): ")
            
            if message_to_send.lower() == 'exit':
                print("Closing Connection...")
                break

            message_bytes = message_to_send.encode('latin-1')
            encrypted_bytes = des_encrypt_cbc(message_bytes, key, iv)

            print(f" -> Sending Ciphertext (Hex): {encrypted_bytes.hex()}")

            connection.sendall(encrypted_bytes)

    except (ConnectionAbortedError, BrokenPipeError):
        print("[Connection Closed]")
    finally:
        connection.close()
        print("[Done]")

# Key changes were also made to start_server and start_client, 
# now both host and client will generate a pair of RSA key (public and private) each.

def start_server(port):
    HOST_IP = get_local_ip()
    
    print("Generating RSA key pair (Host)...")
    rsa_key = RSA.generate(2048)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((HOST_IP, port))
        s.listen(1)
        clear_screen()
        print("--- Hosting Mode ---")
        print(f"Address: {HOST_IP}:{port}") 
        print("\nWaiting for connection...")
        
        conn, addr = s.accept()
        print(f"\n[Connected to {addr}]")

        print("Sending Host's Public Key...")
        conn.sendall(rsa_key.publickey().export_key())

        print("Receiving Client's Public Key...")
        client_pub_bytes = conn.recv(2048)
        client_pub_key = RSA.import_key(client_pub_bytes)
        print("Client's Public Key received.")

        print("Waiting for Secret Key Package...")
        package = conn.recv(512)
        
        encrypted_secret = package[:256]
        signature = package[256:]
        
        print(f"Package Received. \n  Encrypted Secret (Hex): {encrypted_secret.hex()[:30]}...")
        print(f"  Signature (Hex): {signature.hex()[:30]}...")

        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        secret = cipher_rsa.decrypt(encrypted_secret)
        
        is_valid = raw_rsa_verify(secret, signature, client_pub_key)
        
        if is_valid:
            print("\n[SUCCESS] Digital Signature VERIFIED! Sender is Authenticated.")
        else:
            print("\n[WARNING] Digital Signature INVALID! Potential Man-in-the-Middle!")
            return

        key_bytes = secret[:8]
        iv_bytes = secret[8:]
        
        print("Secret Key decrypted successfully.")
        print(f"   DES Key: {key_bytes.decode('latin-1')}")
        print(f"   DES IV : {iv_bytes.decode('latin-1')}")
        
        print("\nStarting Encrypted Chat...")
        chat_loop(conn, key_bytes, iv_bytes)

    except Exception as e:
        print(f"Server Error: {e}")
    finally:
        s.close()

def start_client():
    clear_screen()
    print("--- Client Mode ---")
    address = input("\nInput Host Address (example: 192.168.1.10:9999): ")
    
    print("Generating RSA key pair (Client)...")
    client_rsa_key = RSA.generate(2048)
    
    try:
        host, port = address.split(':')
        port = int(port)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"Connecting to {host}:{port}...")
        s.connect((host, port))
        print("\n[Connected to Host]")

        print("Receiving Host's Public Key...")
        host_pub_bytes = s.recv(2048)
        host_pub_key = RSA.import_key(host_pub_bytes)
        print("Host's Public Key received.")
        
        print("Sending Client's Public Key...")
        s.sendall(client_rsa_key.publickey().export_key())

        print("Generating random DES Key (8 bytes) and IV (8 bytes)...")
        key_bytes = get_random_bytes(8)
        iv_bytes = get_random_bytes(8)
        secret = key_bytes + iv_bytes
        
        print("Signing Secret Key with Client's Private Key...")
        signature = raw_rsa_sign(secret, client_rsa_key)
        
        print("Encrypting Secret Key with Host's Public Key...")
        cipher_rsa = PKCS1_OAEP.new(host_pub_key)
        encrypted_secret = cipher_rsa.encrypt(secret)
        
        print("Sending Package (Encrypted Key + Signature)...")
        s.sendall(encrypted_secret + signature)
        
        print("\nStarting Encrypted Chat...")
        chat_loop(s, key_bytes, iv_bytes)

    except Exception as e:
        print(f"Client Error: {e}")
    finally:
        s.close()

# Main Function

def main():
    clear_screen()
    print("--- DES Encrypted Chat ---")
    
    print("\nChoose Mode:")
    print("1. Host (wait for a Client)")
    print("2. Client (connect to a Host)")
    
    choice = ""
    while choice not in ('1', '2'):
        choice = input("Option (1/2): ")

    if choice == '1':
        port = 0
        while True:
            try:
                port_str = input("Input PORT (example: 9999): ")
                port = int(port_str)
                if not (1024 <= port <= 65535):
                    print("Error: Port must be between 1024 and 65535.")
                else:
                    break
            except ValueError:
                print("Error: Invalid PORT number.")
        
        start_server(port)
        
    elif choice == '2':
        start_client()

if __name__ == "__main__":
    main()
