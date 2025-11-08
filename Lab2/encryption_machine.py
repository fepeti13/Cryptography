
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

    
def ECB(original_text, key, size, encryption_function, padding_mode):
    
    length = len(original_text)
    start_iterator = 0
    end_iterator = BLOCK_SIZE
    while (end_iterator < length):
        encrypted_text += encryption_function(original_text[start_iterator, end_iterator], key)

    padded_block = padding_function(original_text[start_iterator, length], padding_mode)

    pass

def CBC(size, encryption_function, initial_vector, padding_mode):
    pass

def CFB(size, encryption_function, initial_vector, padding_mode):
    pass

def OFB(size, encryption_function, initial_vector, padding_mode):
    pass

def CTR(size, encryption_function, padding_mode):
    pass

def padding_fucntion(text, padding_mode):
    if padding_mode == "zero-padding":
        return zero_padding(text)
    elif padding_mode == "DES_padding":
        return DES_padding(text)
    elif padding_mode == "Schneier_Ferguson_padding":
        return "Scheneier_Ferguson_padding"
    else:
        print("Incorrect padding mode")
        return -1
    
def zero_padding(text):
    length = len(text)
    nr_zeros = BLOCK_SIZE - length
    zeros = ""
    for i in range(nr_zeros):
        zeros += "0"
    
    return text + zeros

def parse_json(path, filename):
    pass


path = os.rootdir()
filename = "config.json"

parse_json(path, filename)