import os
import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# --- FUNGSI HASH MANUAL (PENGGANTI HASHLIB) ---
def manual_hash(data: bytes) -> bytes:
    """
    Fungsi hash sederhana untuk tujuan edukasi (Non-Cryptographic Hash).
    Menghasilkan digest 32-byte dari input data apa pun.
    """
    # Inisialisasi state 32 bytes dengan nilai awal
    state = list(b'INIT_HASH_STATE_32_BYTES_KEY_123') 
    
    for i, byte in enumerate(data):
        # Operasi XOR sederhana dengan rotasi index
        idx = i % 32
        state[idx] = (state[idx] ^ byte) & 0xFF
        
        # Tambahkan sedikit pengacakan (mixing)
        next_idx = (i + 1) % 32
        state[next_idx] = (state[next_idx] + state[idx] + 7) % 256
        
    return bytes(state)

# --- FUNGSI TANDA TANGAN RSA MANUAL ---
def sign_manual(message: bytes, private_key) -> bytes:
    """
    Membuat digital signature secara manual:
    Signature = (Hash(Message) ^ Private_Key_D) mod N
    """
    # 1. Hashing
    digest = manual_hash(message)
    
    # 2. Convert digest (bytes) ke integer
    digest_int = int.from_bytes(digest, byteorder='big')
    
    # 3. Operasi RSA Sign: s = m^d mod n
    # Menggunakan fungsi pow(base, exp, mod) bawaan Python
    signature_int = pow(digest_int, private_key.d, private_key.n)
    
    # 4. Convert kembali ke bytes (256 bytes untuk RSA 2048 bit)
    return signature_int.to_bytes(256, byteorder='big')

def verify_manual(message: bytes, signature: bytes, public_key) -> bool:
    """
    Verifikasi digital signature secara manual:
    Hash(Message) == (Signature ^ Public_Key_E) mod N
    """
    try:
        # 1. Hashing pesan asli
        digest_original = manual_hash(message)
        digest_original_int = int.from_bytes(digest_original, byteorder='big')
        
        # 2. Convert signature ke integer
        signature_int = int.from_bytes(signature, byteorder='big')
        
        # 3. Operasi RSA Verify: m = s^e mod n
        decrypted_digest_int = pow(signature_int, public_key.e, public_key.n)
        
        # 4. Bandingkan hash asli dengan hasil dekripsi signature
        return digest_original_int == decrypted_digest_int
        
    except Exception:
        return False

# --- KONSTANTA & FUNGSI DES (TIDAK BERUBAH) ---
# ... (Bagian DES sama persis seperti tugas sebelumnya) ...

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
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
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
    16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
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

# --- FUNGSI JARINGAN & CHAT (DIMODIFIKASI UNTUK SIGNATURE MANUAL) ---

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

def receive_messages(connection, key, iv, their_public_key):
    # Kunci RSA 2048-bit menghasilkan signature sepanjang 256 bytes
    SIG_SIZE = 256
    
    while True:
        try:
            # Buffer besar untuk menampung signature + ciphertext
            data = connection.recv(4096) 
            if not data:
                print("\n[Connection Lost]")
                break
            
            # --- VALIDASI SIGNATURE ---
            # Format Data: [Signature 256 bytes] + [Ciphertext DES]
            if len(data) < SIG_SIZE:
                print("\n[Error: Paket rusak / terlalu pendek]")
                continue

            signature = data[:SIG_SIZE]
            ciphertext = data[SIG_SIZE:]

            print(f"\r <- Ciphertext (Hex): {ciphertext.hex()}")

            # 1. Dekripsi Pesan (Confidentiality)
            decrypted_bytes = des_decrypt_cbc(ciphertext, key, iv)
            
            # 2. Verifikasi Signature Manual (Authentication & Integrity)
            is_valid = verify_manual(decrypted_bytes, signature, their_public_key)
            
            status_auth = "[VALID SIGNATURE] (Trusted)" if is_valid else "[INVALID SIGNATURE] (WARNING: Message may be forged!)"
            
            message = decrypted_bytes.decode('latin-1')
            
            print(f"    Message: {message}")
            print(f"    Status : {status_auth}")
            print("Enter Message (or 'exit'): ", end="", flush=True)

        except ConnectionResetError:
            print("\n[Connection Lost]")
            break
        except Exception as e:
            print(f"\n[Data Receiving Error: {e}]")
            print("Enter Message (or 'exit'): ", end="", flush=True)

def chat_loop(connection, key, iv, my_private_key, their_public_key):
    try:
        receiver_thread = threading.Thread(
            target=receive_messages, 
            args=(connection, key, iv, their_public_key), 
            daemon=True
        )
        receiver_thread.start()

        while True:
            message_to_send = input("Enter Message (or 'exit'): ")
            
            if message_to_send.lower() == 'exit':
                print("Closing Connection...")
                break

            message_bytes = message_to_send.encode('latin-1')
            
            # 1. Buat Signature Manual (Sign hash dari plaintext)
            signature = sign_manual(message_bytes, my_private_key)
            
            # 2. Enkripsi Pesan dengan DES
            encrypted_bytes = des_encrypt_cbc(message_bytes, key, iv)

            # 3. Kirim: [Signature] + [Ciphertext]
            packet = signature + encrypted_bytes

            print(f" -> Sending Packet (Sig + Cipher): {packet.hex()[:64]}...") 

            connection.sendall(packet)

    except (ConnectionAbortedError, BrokenPipeError):
        print("[Connection Closed]")
    finally:
        connection.close()
        print("[Done]")

def start_server(port):
    HOST_IP = get_local_ip()
    
    # Generate Server Keys
    print("Generating HOST RSA key pair (2048 bits)...")
    server_key = RSA.generate(2048)
    server_private_key = server_key
    server_public_key = server_key.publickey()
    print("HOST keys generated.")
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((HOST_IP, port))
        s.listen(1)
        
        clear_screen()
        print("--- Hosting Mode (With Digital Signature - No hashlib) ---")
        print(f"Address: {HOST_IP}:{port}") 
        print("\nWaiting for connection...")
        
        conn, addr = s.accept()
        print(f"\n[Connected to {addr}]")

        # --- PERTUKARAN KUNCI PUBLIK (2 ARAH) ---
        print("1. Sending Host Public Key to Client...")
        conn.sendall(server_public_key.export_key())
        
        print("2. Receiving Client Public Key...")
        client_pub_bytes = conn.recv(2048)
        client_public_key = RSA.import_key(client_pub_bytes)
        print("   Client Public Key received.")
        
        # --- MENERIMA DES KEY ---
        print("3. Waiting for Encrypted DES Key from Client...")
        encrypted_secret = conn.recv(256) 
        
        # Dekripsi DES key pakai Private Key Server
        cipher_rsa = PKCS1_OAEP.new(server_private_key)
        secret = cipher_rsa.decrypt(encrypted_secret)
        
        key_bytes = secret[:8]
        iv_bytes = secret[8:]
        
        print("   Secret Key decrypted.")
        print(f"   DES Key: {key_bytes.decode('latin-1')}")
        print(f"   DES IV : {iv_bytes.decode('latin-1')}")
        
        print("\nStarting Authenticated Chat...")
        print("Type 'exit' to leave the chat.\n")
        
        chat_loop(conn, key_bytes, iv_bytes, server_private_key, client_public_key)

    except OSError as e:
        print(f"Error: Cannot bind to {HOST_IP}:{port}. Port maybe used.")
    except Exception as e:
        print(f"Server Error: {e}")
    finally:
        s.close()

def start_client():
    clear_screen()
    print("--- Client Mode (With Digital Signature - No hashlib) ---")
    
    # Generate Client Keys
    print("Generating CLIENT RSA key pair (2048 bits)...")
    client_key = RSA.generate(2048)
    client_private_key = client_key
    client_public_key = client_key.publickey()
    print("CLIENT keys generated.")

    address = input("\nInput Host Address (example: 192.168.1.10:9999): ")
    
    try:
        host, port = address.split(':')
        port = int(port)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"Connecting to {host}:{port}...")
        s.connect((host, port))
        
        print("\n[Connected to Host]")

        # --- PERTUKARAN KUNCI PUBLIK (2 ARAH) ---
        print("1. Receiving Host Public Key...")
        server_pub_bytes = s.recv(2048)
        server_public_key = RSA.import_key(server_pub_bytes)
        print("   Host Public Key received.")
        
        print("2. Sending Client Public Key to Host...")
        s.sendall(client_public_key.export_key())

        # --- BUAT & KIRIM DES KEY ---
        print("Generating random DES Key...")
        key_bytes = get_random_bytes(8)
        iv_bytes = get_random_bytes(8)
        secret = key_bytes + iv_bytes
        
        # Enkripsi DES Key pakai Public Key Server
        cipher_rsa = PKCS1_OAEP.new(server_public_key)
        encrypted_secret = cipher_rsa.encrypt(secret)
        
        print(f"3. Sending Encrypted DES Key...")
        s.sendall(encrypted_secret)
        
        print("\nStarting Authenticated Chat...")
        print("Type 'exit' to leave the chat.\n")
        
        chat_loop(s, key_bytes, iv_bytes, client_private_key, server_public_key)

    except ValueError:
        print("Error: Invalid address format.")
    except Exception as e:
        print(f"Client Error: {e}")
    finally:
        s.close()

def main():
    clear_screen()
    print("--- DES Chat with Digital Signature (Tugas 4 - No hashlib) ---")
    
    print("\nChoose Mode:")
    print("1. Host")
    print("2. Client")
    
    choice = ""
    while choice not in ('1', '2'):
        choice = input("Option (1/2): ")

    if choice == '1':
        port = int(input("Input PORT (e.g. 9999): "))
        start_server(port)
    elif choice == '2':
        start_client()

if __name__ == "__main__":
    main()