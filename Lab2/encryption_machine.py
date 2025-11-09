
import os
import json

BLOCK_SIZE = 16    #in bytes

def crypto_machine(mode, original_text, key, size, encryption_function, method, initial_vector, padding_mode):
    if size % 8 != 0:
        print("The size of the array should be divisible by 8")
        return -1
    if mode == "encrypt":
        if method == "ECB":
            return ECB_encrypt(original_text, key, size, encryption_function, padding_mode)
        elif method == "CBC":
            return CBC_encrypt(original_text, key, size, encryption_function, initial_vector, padding_mode)
        elif method == "CFB":
            return CFB_encrypt(original_text, key, size, encryption_function, initial_vector)
        elif method == "OFB":
            return OFB_encrypt(original_text, key, size, encryption_function, initial_vector, padding_mode)
        elif method == "CTR":
            return CTR_encrypt(original_text, key, size, encryption_function, initial_vector)
        else:
            print("Not a valid encryption method")
            return -1
    
    elif mode == "decrypt":
        if method == "ECB":
            return ECB_decrypt(original_text, key, size, encryption_function, padding_mode)
        elif method == "CBC":
            return CBC_decrypt(original_text, key, size, encryption_function, initial_vector, padding_mode)
        elif method == "CFB":
            return CFB_decrypt(original_text, key, size, encryption_function, initial_vector)
        elif method == "OFB":
            return OFB_decrypt(original_text, key, size, encryption_function, initial_vector, padding_mode)
        elif method == "CTR":
            return CTR_decrypt(original_text, key, size, encryption_function, initial_vector)
        else:
            print("Not a valid decryption method")
            return -1

    else:
        print("Not a valid mode, chooose [encrypt/decrypt]")
        return -1

### ECB 

def ECB_encrypt(original_text, key, encryption_function, padding_mode):
    length = len(original_text)
    start_iterator = 0
    end_iterator = BLOCK_SIZE
    encrypted_text = bytearray()
    while (end_iterator <= length):
        encrypted_text += encryption_function(original_text[start_iterator: end_iterator], key)
        start_iterator += BLOCK_SIZE
        end_iterator += BLOCK_SIZE

    if start_iterator < length:
        padded_block = padding_function(bytearray(original_text[start_iterator: length]), padding_mode)
        encrypted_text += encryption_function(padded_block, key)
    
    return encrypted_text

def ECB_decrypt(encrypted_text, key, decryption_function, padding_mode):
    length = len(encrypted_text)
    start_iterator = 0
    end_iterator = BLOCK_SIZE
    decrypted_text = bytearray()
    
    while (end_iterator <= length):
        decrypted_text += decryption_function(encrypted_text[start_iterator: end_iterator], key)
        start_iterator += BLOCK_SIZE
        end_iterator += BLOCK_SIZE
    
    return unpadding_function(decrypted_text, padding_mode)


### CBC

def CBC_encrypt(original_text, key, encryption_function, initial_vector, padding_mode):
    length = len(original_text)
    start_iterator = 0
    end_iterator = BLOCK_SIZE
    encrypted_text = bytearray()

    previous_block = initial_vector

    while (end_iterator <= length):
        xor_output = bytearray( [ x ^ y for x, y in zip(previous_block, original_text[start_iterator : end_iterator]) ] )
        previous_block = encryption_function(xor_output, key)
        encrypted_text += previous_block
        start_iterator += BLOCK_SIZE
        end_iterator += BLOCK_SIZE

    if start_iterator < length:
        padded_block = padding_function(bytearray(original_text[start_iterator: length]), padding_mode)
        xor_output = bytearray( [ x ^ y for x, y in zip(previous_block, padded_block) ] )
        previous_block = encryption_function(xor_output, key)
        encrypted_text += previous_block
        start_iterator += BLOCK_SIZE
        end_iterator += BLOCK_SIZE
    
    return encrypted_text

def CBC_decrypt(encrypted_text, key, decryption_function, initial_vector, padding_mode):
    length = len(encrypted_text)
    start_iterator = 0
    end_iterator = BLOCK_SIZE
    decrypted_text = bytearray()

    previous_block = initial_vector

    while (end_iterator <= length):
        current_encrypted_block = encrypted_text[start_iterator:end_iterator]
        decrypted_block = decryption_function(current_encrypted_block, key)
        xor_output = bytearray([x ^ y for x, y in zip(previous_block, decrypted_block)])
        decrypted_text += xor_output
        previous_block = current_encrypted_block
        start_iterator += BLOCK_SIZE
        end_iterator += BLOCK_SIZE
    
    return unpadding_function(decrypted_text, padding_mode)

### CFB

def CFB_encrypt(original_text, key, encryption_function, initial_vector):
    length = len(original_text)
    start_iterator = 0
    end_iterator = BLOCK_SIZE
    encrypted_text = bytearray()

    previous_block = initial_vector

    while (end_iterator <= length):
        encryption_output = encryption_function(previous_block, key)
        xor_output = bytearray( [ x ^ y for x, y in zip(encryption_output, original_text[start_iterator:end_iterator]) ] )
        encrypted_text += xor_output
        previous_block = xor_output
        start_iterator += BLOCK_SIZE
        end_iterator += BLOCK_SIZE

    if start_iterator < length:
        last_block_length = length - start_iterator
        encryption_output = encryption_function(previous_block, key)
        xor_output = bytearray( [x ^ y for x, y in zip(original_text[start_iterator:], encryption_output[:last_block_length])])
        encrypted_text += xor_output
        
    return encrypted_text

def CFB_decrypt(encrypted_text, key, encryption_function, initial_vector):
    length = len(encrypted_text)
    start_iterator = 0
    end_iterator = BLOCK_SIZE
    decrypted_text = bytearray()

    previous_block = initial_vector

    while (end_iterator <= length):
        encryption_output = encryption_function(previous_block, key)
        xor_output = bytearray([x ^ y for x, y in zip(encryption_output, encrypted_text[start_iterator:end_iterator])])
        decrypted_text += xor_output
        previous_block = encrypted_text[start_iterator:end_iterator]
        start_iterator += BLOCK_SIZE
        end_iterator += BLOCK_SIZE

    if start_iterator < length:
        last_block_length = length - start_iterator
        encryption_output = encryption_function(previous_block, key)
        xor_output = bytearray([x ^ y for x, y in zip(encrypted_text[start_iterator:], encryption_output[:last_block_length])])
        decrypted_text += xor_output
        
    return decrypted_text

### OFB

def OFB_encrypt(original_text, key, encryption_function, initial_vector):
    length = len(original_text)
    start_iterator = 0
    end_iterator = BLOCK_SIZE
    encrypted_text = bytearray()

    previous_block = initial_vector

    while (end_iterator <= length):
        encryption_output = encryption_function(previous_block, key)
        xor_output = bytearray( [ x ^ y for x, y in zip(encryption_output, original_text[start_iterator:end_iterator]) ] )
        encrypted_text += xor_output
        previous_block = encryption_output
        start_iterator += BLOCK_SIZE
        end_iterator += BLOCK_SIZE

    if start_iterator < length:
        last_block_length = length - start_iterator
        encryption_output = encryption_function(previous_block, key)
        xor_output = bytearray( [x ^ y for x, y in zip(original_text[start_iterator:], encryption_output[:last_block_length])])
        encrypted_text += xor_output
        
    return encrypted_text

def OFB_decrypt(encrypted_text, key, encryption_function, initial_vector):
    length = len(encrypted_text)
    start_iterator = 0
    end_iterator = BLOCK_SIZE
    decrypted_text = bytearray()

    previous_block = initial_vector

    while (end_iterator <= length):
        encryption_output = encryption_function(previous_block, key)
        xor_output = bytearray([x ^ y for x, y in zip(encryption_output, encrypted_text[start_iterator:end_iterator])])
        decrypted_text += xor_output
        previous_block = encryption_output
        start_iterator += BLOCK_SIZE
        end_iterator += BLOCK_SIZE

    if start_iterator < length:
        last_block_length = length - start_iterator
        encryption_output = encryption_function(previous_block, key)
        xor_output = bytearray([x ^ y for x, y in zip(encrypted_text[start_iterator:], encryption_output[:last_block_length])])
        decrypted_text += xor_output
        
    return decrypted_text


### CTR

def CTR_encrypt(original_text, key, encryption_function, nonce):    #Nonce = Number used ONCE (very similar to IV but it is 8 bytes and it can be predictable)
    length = len(original_text)
    start_iterator = 0
    end_iterator = BLOCK_SIZE
    encrypted_text = bytearray()
    counter = 0
    while (end_iterator <= length):
        counter_block = nonce + counter.to_bytes(8, 'big')
        
        encryption_output = encryption_function(counter_block, key)
        xor_output = bytearray([x ^ y for x, y in zip(encryption_output, original_text[start_iterator: end_iterator])])
        encrypted_text += xor_output
        start_iterator += BLOCK_SIZE
        end_iterator += BLOCK_SIZE
        counter += 1

    if start_iterator < length:
        counter_block = nonce + counter.to_bytes(8, 'big')
        
        encryption_output = encryption_function(counter_block, key)
        xor_output = bytearray([x ^ y for x, y in zip(encryption_output, original_text[start_iterator:])])
        encrypted_text += xor_output

    return encrypted_text

def CTR_decrypt(encrypted_text, key, encryption_function, nonce):
    length = len(encrypted_text)
    start_iterator = 0
    end_iterator = BLOCK_SIZE
    decrypted_text = bytearray()
    counter = 0
    while (end_iterator <= length):
        counter_block = nonce + counter.to_bytes(8, 'big')
        
        encryption_output = encryption_function(counter_block, key)
        xor_output = bytearray([x ^ y for x, y in zip(encryption_output, encrypted_text[start_iterator:end_iterator])])
        decrypted_text += xor_output
        start_iterator += BLOCK_SIZE
        end_iterator += BLOCK_SIZE
        counter += 1

    if start_iterator < length:
        counter_block = nonce + counter.to_bytes(8, 'big')
        
        encryption_output = encryption_function(counter_block, key)
        xor_output = bytearray([x ^ y for x, y in zip(encryption_output, encrypted_text[start_iterator:])])
        decrypted_text += xor_output

    return decrypted_text


### padding

def padding_function(text, padding_mode):
    if padding_mode == "zero-padding":
        return zero_padding(text)
    elif padding_mode == "DES_padding":
        return DES_padding(text)
    elif padding_mode == "Schneier_Ferguson_padding":
        return Schneier_Ferguson_padding(text)
    else:
        print("Incorrect padding mode")
        return -1
    
def zero_padding(text):
    padding_length = BLOCK_SIZE - len(text)        #len gives the lenght in bytes
    text.extend(b'\x00' * padding_length)
    return text

def DES_padding(text):
    padding_length = BLOCK_SIZE - len(text)
    text.extend(b'\x80' + b'\x00' * (padding_length - 1))
    return text

def Schneier_Ferguson_padding(text):
    padding_length = (BLOCK_SIZE - len(text))
    text.extend(bytes([padding_length] * padding_length))
    return text


### unpadding

def unpadding_function(text, padding_mode):
    if padding_mode == "zero-padding":
        return zero_unpadding(text)
    elif padding_mode == "DES_padding":
        return DES_unpadding(text)
    elif padding_mode == "Schneier_Ferguson_padding":
        return Schneier_Ferguson_unpadding(text)
    else:
        raise ValueError(f"Incorrect padding mode: {padding_mode}")

def zero_unpadding(text):
    while len(text) > 0 and text[-1] == 0:
        text.pop()
    return text

def DES_unpadding(text):
    while len(text) > 0 and text[-1] == 0:
        text.pop()
    if len(text) > 0 and text[-1] == 0x80:
        text.pop()
    return text

def Schneier_Ferguson_unpadding(text):
    padding_length = text[-1]
    return text[:-padding_length]


### starter point

def parse_json(filename):
    with open(filename, 'r') as f:
        config = json.load(f)
    
    validate_config(config)
    return config

def validate_config(config):
    required_fields = ["input_file", "output_file", "mode", "method", "key", "encryption_function"]
    
    for field in required_fields:
        if field not in config:
            raise ValueError(f"Missing required field: {field}")
    
    valid_modes = ["encrypt", "decrypt"]
    if config["mode"] not in valid_modes:
        raise ValueError(f"Invalid mode: {config['mode']}. Must be one of {valid_modes}")
    
    valid_methods = ["ECB", "CBC", "CFB", "OFB", "CTR"]
    if config["method"] not in valid_methods:
        raise ValueError(f"Invalid method: {config['method']}. Must be one of {valid_methods}")
    
    valid_ciphers = ["AES", "DES"]
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
    
    if cipher == "AES":
        if len(key) not in [16, 24, 32]:
            raise ValueError(f"AES key must be 16, 24, or 32 bytes. Got {len(key)}")
        
        if method in ["CBC", "CFB", "OFB"] and "initial_vector" in config:
            iv = config["initial_vector"]
            if len(iv) != 16:
                raise ValueError(f"AES initial_vector must be 16 bytes. Got {len(iv)}")
        
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
    

try:
    config = parse_json('config.json')
    print("Config valid!")
    print(f"Method: {config['method']}")
except ValueError as e:
    print(f"Config error: {e}")
except FileNotFoundError:
    print("Config file not found!")
except json.JSONDecodeError as e:
    print(f"Invalid JSON: {e}")