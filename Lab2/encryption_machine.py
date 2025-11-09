import json
import os
import sys

BLOCK_SIZE = 16

def main(config_path=None):
    if config_path is None:
        if len(sys.argv) > 1:
            config_path = sys.argv[1]
        else:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            config_path = os.path.join(script_dir, 'config.json')
    
    print(f"Loading config from: {config_path}")
    
    if not os.path.exists(config_path):
        print(f"Error: Config file not found: {config_path}")
        print(f"Current working directory: {os.getcwd()}")
        print(f"Script directory: {os.path.dirname(os.path.abspath(__file__))}")
        sys.exit(1)
    
    try:
        config = load_config(config_path)
        print("Config loaded and validated successfully!")
        
        block_size = config.get("block_size", 128) // 8
        print(f"Using block size: {block_size} bytes ({block_size * 8} bits)")
        
        encrypt_func, decrypt_func = get_cipher_functions(config["encryption_function"])
        
        input_file = config["input_file"]
        if not os.path.isabs(input_file):
            script_dir = os.path.dirname(os.path.abspath(__file__))
            input_file = os.path.join(script_dir, input_file)
        
        input_data = read_file(input_file)
        
        if config["mode"] == "encrypt":
            result = process_encryption(input_data, config, encrypt_func)
        else:
            result = process_decryption(input_data, config, decrypt_func)
        
        output_file = config["output_file"]
        if not os.path.isabs(output_file):
            script_dir = os.path.dirname(os.path.abspath(__file__))
            output_file = os.path.join(script_dir, output_file)
        
        write_file(output_file, result)
        
        print(f"Success! Processed {len(result)} bytes")
        print(f"Output written to: {output_file}")
        
    except ValueError as e:
        print(f"Config error: {e}")
    except FileNotFoundError as e:
        print(f"File not found: {e}")
    except json.JSONDecodeError as e:
        print(f"Invalid JSON: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

def load_config(filename):
    with open(filename, 'r') as f:
        config = json.load(f)
    validate_config(config)
    return config

def validate_config(config):
    required_fields = ["input_file", "output_file", "mode", "method", "key", "encryption_function"]
    
    for field in required_fields:
        if field not in config:
            raise ValueError(f"Missing required field: {field}")
    
    if "block_size" in config:
        if config["block_size"] % 8 != 0:
            raise ValueError(f"block_size must be divisible by 8. Got {config['block_size']}")
    
    valid_modes = ["encrypt", "decrypt"]
    if config["mode"] not in valid_modes:
        raise ValueError(f"Invalid mode: {config['mode']}. Must be one of {valid_modes}")
    
    valid_methods = ["ECB", "CBC", "CFB", "OFB", "CTR"]
    if config["method"] not in valid_methods:
        raise ValueError(f"Invalid method: {config['method']}. Must be one of {valid_methods}")
    
    valid_ciphers = ["AES", "DES", "CUSTOM"]
    if config["encryption_function"] not in valid_ciphers:
        raise ValueError(f"Invalid encryption_function: {config['encryption_function']}. Must be one of {valid_ciphers}")
    
    if config["method"] in ["ECB", "CBC"]:
        if "padding_mode" not in config or not config["padding_mode"]:
            raise ValueError(f"{config['method']} requires padding_mode")
        
        valid_padding = ["zero-padding", "DES_padding", "Schneier_Ferguson_padding"]
        if config["padding_mode"] not in valid_padding:
            raise ValueError(f"Invalid padding_mode: {config['padding_mode']}. Must be one of {valid_padding}")
    
    if config["method"] in ["CBC", "CFB", "OFB"]:
        if "initial_vector" not in config or not config["initial_vector"]:
            raise ValueError(f"{config['method']} requires initial_vector")
    
    if config["method"] == "CTR":
        if "nonce" not in config or not config["nonce"]:
            raise ValueError("CTR requires nonce")
    
    validate_key_lengths(config)

def validate_key_lengths(config):
    cipher = config["encryption_function"]
    key = config["key"]
    method = config["method"]
    block_size = config.get("block_size", 128) // 8
    
    if cipher == "AES":
        if len(key) not in [16, 24, 32]:
            raise ValueError(f"AES key must be 16, 24, or 32 bytes. Got {len(key)}")
        
        if method in ["CBC", "CFB", "OFB"] and "initial_vector" in config:
            iv = config["initial_vector"]
            if len(iv) != block_size:
                raise ValueError(f"AES initial_vector must be {block_size} bytes. Got {len(iv)}")
        
        if method == "CTR" and "nonce" in config:
            nonce = config["nonce"]
            if len(nonce) != 8:
                raise ValueError(f"AES CTR nonce should be 8 bytes. Got {len(nonce)}")
    
    elif cipher == "DES":
        if len(key) != 8:
            raise ValueError(f"DES key must be 8 bytes. Got {len(key)}")
        
        if method in ["CBC", "CFB", "OFB"] and "initial_vector" in config:
            iv = config["initial_vector"]
            if len(iv) != 8:
                raise ValueError(f"DES initial_vector must be 8 bytes. Got {len(iv)}")
    
    elif cipher == "CUSTOM":
        if method in ["CBC", "CFB", "OFB"] and "initial_vector" in config:
            iv = config["initial_vector"]
            if len(iv) != block_size:
                raise ValueError(f"CUSTOM initial_vector must be {block_size} bytes. Got {len(iv)}")

def get_cipher_functions(cipher_name):
    if cipher_name == "AES":
        from Crypto.Cipher import AES
        
        def encrypt_block(block, key):
            cipher = AES.new(key, AES.MODE_ECB)
            return cipher.encrypt(bytes(block))
        
        def decrypt_block(block, key):
            cipher = AES.new(key, AES.MODE_ECB)
            return cipher.decrypt(bytes(block))
        
        return encrypt_block, decrypt_block
    
    elif cipher_name == "DES":
        from Crypto.Cipher import DES
        
        def encrypt_block(block, key):
            cipher = DES.new(key, DES.MODE_ECB)
            return cipher.encrypt(bytes(block))
        
        def decrypt_block(block, key):
            cipher = DES.new(key, DES.MODE_ECB)
            return cipher.decrypt(bytes(block))
        
        return encrypt_block, decrypt_block
    
    elif cipher_name == "CUSTOM":
        return custom_encrypt_block, custom_decrypt_block
    
    else:
        raise ValueError(f"Unknown cipher: {cipher_name}")

def read_file(filename):
    with open(filename, 'rb') as f:
        return bytearray(f.read())

def write_file(filename, data):
    with open(filename, 'wb') as f:
        f.write(data)

def process_encryption(data, config, encrypt_func):
    method = config["method"]
    key = config["key"].encode('utf-8')
    block_size = config.get("block_size", 128) // 8
    
    if method == "ECB":
        return ECB_encrypt(data, key, encrypt_func, config["padding_mode"], block_size)
    
    elif method == "CBC":
        iv = config["initial_vector"].encode('utf-8')
        return CBC_encrypt(data, key, encrypt_func, iv, config["padding_mode"], block_size)
    
    elif method == "CFB":
        iv = config["initial_vector"].encode('utf-8')
        return CFB_encrypt(data, key, encrypt_func, iv, block_size)
    
    elif method == "OFB":
        iv = config["initial_vector"].encode('utf-8')
        return OFB_encrypt(data, key, encrypt_func, iv, block_size)
    
    elif method == "CTR":
        nonce = config["nonce"].encode('utf-8')
        return CTR_encrypt(data, key, encrypt_func, nonce, block_size)
    
    else:
        raise ValueError(f"Invalid encryption method: {method}")

def process_decryption(data, config, decrypt_func):
    method = config["method"]
    key = config["key"].encode('utf-8')
    block_size = config.get("block_size", 128) // 8
    
    if method == "ECB":
        return ECB_decrypt(data, key, decrypt_func, config["padding_mode"], block_size)
    
    elif method == "CBC":
        iv = config["initial_vector"].encode('utf-8')
        return CBC_decrypt(data, key, decrypt_func, iv, config["padding_mode"], block_size)
    
    elif method == "CFB":
        iv = config["initial_vector"].encode('utf-8')
        return CFB_decrypt(data, key, decrypt_func, iv, block_size)
    
    elif method == "OFB":
        iv = config["initial_vector"].encode('utf-8')
        return OFB_decrypt(data, key, decrypt_func, iv, block_size)
    
    elif method == "CTR":
        nonce = config["nonce"].encode('utf-8')
        return CTR_decrypt(data, key, decrypt_func, nonce, block_size)
    
    else:
        raise ValueError(f"Invalid decryption method: {method}")

def ECB_encrypt(original_text, key, encryption_function, padding_mode, block_size):
    length = len(original_text)
    start_iterator = 0
    encrypted_text = bytearray()
    
    while start_iterator + block_size <= length:
        end_iterator = start_iterator + block_size
        encrypted_text.extend(encryption_function(original_text[start_iterator:end_iterator], key))
        start_iterator += block_size

    if start_iterator < length:
        padded_block = padding_function(bytearray(original_text[start_iterator:]), padding_mode, block_size)
        encrypted_text.extend(encryption_function(padded_block, key))
    
    return encrypted_text

def ECB_decrypt(encrypted_text, key, decryption_function, padding_mode, block_size):
    length = len(encrypted_text)
    start_iterator = 0
    decrypted_text = bytearray()
    
    while start_iterator + block_size <= length:
        end_iterator = start_iterator + block_size
        decrypted_text.extend(decryption_function(encrypted_text[start_iterator:end_iterator], key))
        start_iterator += block_size
    
    return unpadding_function(decrypted_text, padding_mode, block_size)

def CBC_encrypt(original_text, key, encryption_function, initial_vector, padding_mode, block_size):
    length = len(original_text)
    start_iterator = 0
    encrypted_text = bytearray()
    previous_block = initial_vector

    while start_iterator + block_size <= length:
        end_iterator = start_iterator + block_size
        xor_output = bytearray([x ^ y for x, y in zip(previous_block, original_text[start_iterator:end_iterator])])
        previous_block = encryption_function(xor_output, key)
        encrypted_text.extend(previous_block)
        start_iterator += block_size

    if start_iterator < length:
        padded_block = padding_function(bytearray(original_text[start_iterator:]), padding_mode, block_size)
        xor_output = bytearray([x ^ y for x, y in zip(previous_block, padded_block)])
        previous_block = encryption_function(xor_output, key)
        encrypted_text.extend(previous_block)
    
    return encrypted_text

def CBC_decrypt(encrypted_text, key, decryption_function, initial_vector, padding_mode, block_size):
    length = len(encrypted_text)
    start_iterator = 0
    decrypted_text = bytearray()
    previous_block = initial_vector

    while start_iterator + block_size <= length:
        end_iterator = start_iterator + block_size
        current_encrypted_block = encrypted_text[start_iterator:end_iterator]
        decrypted_block = decryption_function(current_encrypted_block, key)
        xor_output = bytearray([x ^ y for x, y in zip(previous_block, decrypted_block)])
        decrypted_text.extend(xor_output)
        previous_block = current_encrypted_block
        start_iterator += block_size
    
    return unpadding_function(decrypted_text, padding_mode, block_size)

def CFB_encrypt(original_text, key, encryption_function, initial_vector, block_size):
    length = len(original_text)
    start_iterator = 0
    encrypted_text = bytearray()
    previous_block = initial_vector

    while start_iterator + block_size <= length:
        end_iterator = start_iterator + block_size
        encryption_output = encryption_function(previous_block, key)
        plaintext_block = original_text[start_iterator:end_iterator]
        xor_output = bytearray([x ^ y for x, y in zip(encryption_output, plaintext_block)])
        encrypted_text.extend(xor_output)
        previous_block = bytearray(xor_output)
        start_iterator += block_size

    if start_iterator < length:
        encryption_output = encryption_function(previous_block, key)
        remaining = original_text[start_iterator:]
        xor_output = bytearray([x ^ y for x, y in zip(encryption_output, remaining)])
        encrypted_text.extend(xor_output)
        
    return encrypted_text

def CFB_decrypt(encrypted_text, key, encryption_function, initial_vector, block_size):
    length = len(encrypted_text)
    start_iterator = 0
    decrypted_text = bytearray()
    previous_block = initial_vector

    while start_iterator + block_size <= length:
        end_iterator = start_iterator + block_size
        current_encrypted = encrypted_text[start_iterator:end_iterator]
        
        encryption_output = encryption_function(previous_block, key)
        xor_output = bytearray([x ^ y for x, y in zip(encryption_output, current_encrypted)])
        decrypted_text.extend(xor_output)
        
        previous_block = bytearray(current_encrypted)
        start_iterator += block_size

    if start_iterator < length:
        encryption_output = encryption_function(previous_block, key)
        remaining = encrypted_text[start_iterator:]
        xor_output = bytearray([x ^ y for x, y in zip(encryption_output, remaining)])
        decrypted_text.extend(xor_output)
        
    return decrypted_text

def OFB_encrypt(original_text, key, encryption_function, initial_vector, block_size):
    length = len(original_text)
    start_iterator = 0
    encrypted_text = bytearray()
    previous_block = initial_vector

    while start_iterator + block_size <= length:
        end_iterator = start_iterator + block_size
        encryption_output = encryption_function(previous_block, key)
        xor_output = bytearray([x ^ y for x, y in zip(encryption_output, original_text[start_iterator:end_iterator])])
        encrypted_text.extend(xor_output)
        previous_block = bytearray(encryption_output)
        start_iterator += block_size

    if start_iterator < length:
        encryption_output = encryption_function(previous_block, key)
        remaining = original_text[start_iterator:]
        xor_output = bytearray([x ^ y for x, y in zip(encryption_output, remaining)])
        encrypted_text.extend(xor_output)
        
    return encrypted_text

def OFB_decrypt(encrypted_text, key, encryption_function, initial_vector, block_size):
    length = len(encrypted_text)
    start_iterator = 0
    decrypted_text = bytearray()
    previous_block = initial_vector

    while start_iterator + block_size <= length:
        end_iterator = start_iterator + block_size
        encryption_output = encryption_function(previous_block, key)
        xor_output = bytearray([x ^ y for x, y in zip(encryption_output, encrypted_text[start_iterator:end_iterator])])
        decrypted_text.extend(xor_output)
        previous_block = bytearray(encryption_output)
        start_iterator += block_size

    if start_iterator < length:
        encryption_output = encryption_function(previous_block, key)
        remaining = encrypted_text[start_iterator:]
        xor_output = bytearray([x ^ y for x, y in zip(encryption_output, remaining)])
        decrypted_text.extend(xor_output)
        
    return decrypted_text

def CTR_encrypt(original_text, key, encryption_function, nonce, block_size):
    length = len(original_text)
    start_iterator = 0
    encrypted_text = bytearray()
    counter = 0
    
    counter_size = block_size - len(nonce)
    
    while start_iterator + block_size <= length:
        end_iterator = start_iterator + block_size
        counter_block = nonce + counter.to_bytes(counter_size, 'big')
        encryption_output = encryption_function(counter_block, key)
        xor_output = bytearray([x ^ y for x, y in zip(encryption_output, original_text[start_iterator:end_iterator])])
        encrypted_text.extend(xor_output)
        start_iterator += block_size
        counter += 1

    if start_iterator < length:
        counter_block = nonce + counter.to_bytes(counter_size, 'big')
        encryption_output = encryption_function(counter_block, key)
        remaining = original_text[start_iterator:]
        xor_output = bytearray([x ^ y for x, y in zip(encryption_output, remaining)])
        encrypted_text.extend(xor_output)

    return encrypted_text

def CTR_decrypt(encrypted_text, key, encryption_function, nonce, block_size):
    length = len(encrypted_text)
    start_iterator = 0
    decrypted_text = bytearray()
    counter = 0
    
    counter_size = block_size - len(nonce)
    
    while start_iterator + block_size <= length:
        end_iterator = start_iterator + block_size
        counter_block = nonce + counter.to_bytes(counter_size, 'big')
        encryption_output = encryption_function(counter_block, key)
        xor_output = bytearray([x ^ y for x, y in zip(encryption_output, encrypted_text[start_iterator:end_iterator])])
        decrypted_text.extend(xor_output)
        start_iterator += block_size
        counter += 1

    if start_iterator < length:
        counter_block = nonce + counter.to_bytes(counter_size, 'big')
        encryption_output = encryption_function(counter_block, key)
        remaining = encrypted_text[start_iterator:]
        xor_output = bytearray([x ^ y for x, y in zip(encryption_output, remaining)])
        decrypted_text.extend(xor_output)

    return decrypted_text

def padding_function(text, padding_mode, block_size):
    if padding_mode == "zero-padding":
        return zero_padding(text, block_size)
    elif padding_mode == "DES_padding":
        return DES_padding(text, block_size)
    elif padding_mode == "Schneier_Ferguson_padding":
        return Schneier_Ferguson_padding(text, block_size)
    else:
        raise ValueError(f"Invalid padding mode: {padding_mode}")

def zero_padding(text, block_size):
    padding_length = block_size - len(text)
    text.extend(b'\x00' * padding_length)
    return text

def DES_padding(text, block_size):
    padding_length = block_size - len(text)
    text.extend(b'\x80' + b'\x00' * (padding_length - 1))
    return text

def Schneier_Ferguson_padding(text, block_size):
    padding_length = block_size - len(text)
    text.extend(bytes([padding_length] * padding_length))
    return text

def unpadding_function(text, padding_mode, block_size):
    if padding_mode == "zero-padding":
        return zero_unpadding(text, block_size)
    elif padding_mode == "DES_padding":
        return DES_unpadding(text, block_size)
    elif padding_mode == "Schneier_Ferguson_padding":
        return Schneier_Ferguson_unpadding(text, block_size)
    else:
        raise ValueError(f"Invalid padding mode: {padding_mode}")

def zero_unpadding(text, block_size):
    while len(text) > 0 and text[-1] == 0:
        text.pop()
    return text

def DES_unpadding(text, block_size):
    while len(text) > 0 and text[-1] == 0:
        text.pop()
    if len(text) > 0 and text[-1] == 0x80:
        text.pop()
    return text

def Schneier_Ferguson_unpadding(text, block_size):
    if len(text) == 0:
        return text
    padding_length = text[-1]
    if padding_length > len(text) or padding_length > block_size or padding_length == 0:
        return text
    return text[:-padding_length]

def custom_encrypt_block(block, key):
    if len(block) != 16:
        raise ValueError("Block must be 16 bytes")
    
    block = bytearray(block)
    key = bytearray(key)
    
    result = bytearray(block)
    
    for i in range(16):
        key_byte = key[i % len(key)]
        result[i] = (result[i] + key_byte) % 256
    
    result = rotate_bytes(result, 3)
    
    for i in range(16):
        key_byte = key[(i + 7) % len(key)]
        result[i] = (result[i] + key_byte) % 256
    
    return bytes(result)

def custom_decrypt_block(block, key):
    if len(block) != 16:
        raise ValueError("Block must be 16 bytes")
    
    block = bytearray(block)
    key = bytearray(key)
    
    result = bytearray(block)
    
    for i in range(16):
        key_byte = key[(i + 7) % len(key)]
        result[i] = (result[i] - key_byte) % 256
    
    result = rotate_bytes(result, -3)
    
    for i in range(16):
        key_byte = key[i % len(key)]
        result[i] = (result[i] - key_byte) % 256
    
    return bytes(result)

def rotate_bytes(data, amount):
    amount = amount % len(data)
    return data[amount:] + data[:amount]

if __name__ == "__main__":
    main()