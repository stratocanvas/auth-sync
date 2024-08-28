import secrets
def generate_aes_key(key_size=32):  # AES256 GCM
    key = secrets.token_bytes(key_size)  
    hex_key = key.hex()
    return hex_key

if __name__ == "__main__":
    hex_key = generate_aes_key()