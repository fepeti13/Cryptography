
import os

BLOCK_SIZE = 16    #in bytes

def encryption_machine(original_text, key, size, encryption_function, method, initial_vector, padding_mode):
    if size % 8 != 0:
        print("The size of the array should be divisible by 8")
        return -1
    
    if method == "ECB":
        ECB(original_text, key, size, encryption_function, padding_mode)
    elif method == "CBC":
        CBC(original_text, key, size, encryption_function, initial_vector, padding_mode)
    elif method == "CFB":
        CFB(original_text, key, size, encryption_function, initial_vector, padding_mode)
    elif method == "OFB":
        OFB(original_text, key, size, encryption_function, initial_vector, padding_mode)
    elif method == "CTR":
        CTR(original_text, key, size, encryption_function, padding_mode)

    
def ECB(original_text, key, encryption_function, padding_mode):
    length = len(original_text)
    start_iterator = 0
    end_iterator = BLOCK_SIZE
    encrypted_text = bytearray()
    while (end_iterator <= length):
        encrypted_text += encryption_function(original_text[start_iterator: end_iterator], key)
        start_iterator += BLOCK_SIZE
        end_iterator += BLOCK_SIZE

    if start_iterator < length:
        padded_block = padding_function(original_text[start_iterator: length], padding_mode)
        encrypted_text += encryption_function(padded_block, key)
    
    return encrypted_text

def CBC(original_text, key, encryption_function, initial_vector, padding_mode):
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
        padded_block = padding_function(original_text[start_iterator: length], padding_mode)
        xor_output = bytearray( [ x ^ y for x, y in zip(previous_block, padded_block) ] )
        previous_block = encryption_function(xor_output, key)
        encrypted_text += previous_block
        start_iterator += BLOCK_SIZE
        end_iterator += BLOCK_SIZE
    
    return encrypted_text

def CFB(original_text, key, encryption_function, initial_vector):
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

def OFB(original_text, key, encryption_function, initial_vector):
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

def CTR(size, encryption_function, padding_mode):
    pass

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
    padding_length = BLOCK_SIZE - len(text)                     #len gives the lenght in bytes
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

def parse_json(path, filename):
    pass


path = os.rootdir()
filename = "config.json"

parse_json(path, filename)