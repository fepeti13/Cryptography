
import os

BLOCK_SIZE = 128    #in bits

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
    while (end_iterator < length):
        encrypted_text += encryption_function(original_text[start_iterator: end_iterator], key)
        start_iterator += BLOCK_SIZE
        end_iterator += BLOCK_SIZE

    if start_iterator < length:
        padded_block = padding_function(original_text[start_iterator: length], padding_mode)
        encrypted_text += encryption_function(padded_block, key)
    pass

def CBC(size, encryption_function, initial_vector, padding_mode):
    pass

def CFB(size, encryption_function, initial_vector, padding_mode):
    pass

def OFB(size, encryption_function, initial_vector, padding_mode):
    pass

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
    return text.extend(b'\x00' * padding_length)
    
def DES_padding(text):
    padding_length = BLOCK_SIZE - len(text)
    return text.extend(b'\x80' + b'\x00' * (padding_length - 1))

def Schneier_Ferguson_padding(text):
    padding_length = (BLOCK_SIZE - len(text))
    text.extend(bytes([padding_length] * padding_length))
    return text

def parse_json(path, filename):
    pass


path = os.rootdir()
filename = "config.json"

parse_json(path, filename)