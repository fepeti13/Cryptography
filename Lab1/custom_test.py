from crypto import (decrypt_vigenere) 
import os

script_dir = os.path.dirname(os.path.abspath(__file__))

words_path = "/usr/share/dict/words"
ciphertext_path = os.path.join(script_dir, "secret_message.txt")

def get_text(path):
    with open(path, 'r') as f:
        text = f.read()
    
    return text

possible_keys = get_text(words_path)
ciphertext = get_text(ciphertext_path)

print(ciphertext)

decrypt_vigenere(ciphertext, possible_keys)