#!/usr/bin/env python3 -tt
"""
File: crypto-console.py
-----------------------
Implements a console menu to interact with the cryptography functions exported
by the crypto module.

Enhanced version with binary encryption support and rail fence cipher.
"""
import random

from crypto import (encrypt_caesar, decrypt_caesar,
                    encrypt_caesar_binary, decrypt_caesar_binary,
                    encrypt_vigenere, decrypt_vigenere_with_key,
                    encrypt_vigenere_binary, decrypt_vigenere_binary,
                    encrypt_scytale, decrypt_scytale,
                    encrypt_rail_fence, decrypt_rail_fence,
                    generate_private_key, create_public_key,
                    encrypt_mh, decrypt_mh,
                    decrypt_vigenere)


#############################
# GENERAL CONSOLE UTILITIES #
#############################

def get_tool():
    print("* Tool *")
    print("Available ciphers:")
    print("  (C)aesar - Simple shift cipher")
    print("  (V)igenere - Keyword-based cipher")
    print("  (S)cytale - Transposition cipher")
    print("  (R)ail Fence - Zigzag transposition cipher")
    print("  (M)erkle-Hellman - Public key cryptosystem")
    print("  (B)inary Encryption - Encrypt files (images, audio, etc.)")
    print("  (I)ntelligent Codebreaker - Break Vigenere without knowing the key")
    return _get_selection("Choose a cipher: ", "CVRSMBИ")


def get_action():
    """Return true iff encrypt"""
    print("* Action *")
    return _get_selection("(E)ncrypt or (D)ecrypt? ", "ED")


def get_filename():
    filename = input("Filename? ")
    while not filename:
        filename = input("Filename? ")
    return filename


def get_input(binary=False):
    print("* Input *")
    choice = _get_selection("(F)ile or (S)tring? ", "FS")
    if choice == 'S':
        text = input("Enter a string: ").strip().upper()
        while not text:
            text = input("Enter a string: ").strip().upper()
        if binary:
            return bytes(text, encoding='utf8')
        return text
    else:
        filename = get_filename()
        flags = 'r'
        if binary:
            flags += 'b'
        with open(filename, flags) as infile:
            return infile.read()


def set_output(output, binary=False):
    print("* Output *")
    choice = _get_selection("(F)ile or (S)tring? ", "FS")
    if choice == 'S':
        print(output)
    else:
        filename = get_filename()
        flags = 'w'
        if binary:
            flags += 'b'
        with open(filename, flags) as outfile:
            print("Writing data to {}...".format(filename))
            outfile.write(output)


def _get_selection(prompt, options):
    choice = input(prompt).upper()
    while not choice or choice[0] not in options:
        choice = input("Please enter one of {}. {}".format('/'.join(options), prompt)).upper()
    return choice[0]


def get_yes_or_no(prompt, reprompt=None):
    """
    Asks the user whether they would like to continue.
    Responses that begin with a `Y` return True. (case-insensitively)
    Responses that begin with a `N` return False. (case-insensitively)
    All other responses (including '') cause a reprompt.
    """
    if not reprompt:
        reprompt = prompt

    choice = input("{} (Y/N) ".format(prompt)).upper()
    while not choice or choice[0] not in ['Y', 'N']:
        choice = input("Please enter either 'Y' or 'N'. {} (Y/N)? ".format(reprompt)).upper()
    return choice[0] == 'Y'


def clean_caesar(text):
    """Convert text to a form compatible with the preconditions imposed by Caesar cipher"""
    return text.upper()


def clean_vigenere(text):
    return ''.join(ch for ch in text.upper() if ch.isupper())


def clean_scytale(text):
    return text.upper()


def run_caesar():
    action = get_action()
    encrypting = action == 'E'
    data = clean_caesar(get_input(binary=False))

    print("* Transform *")
    print("{}crypting {} using Caesar cipher...".format('En' if encrypting else 'De', data))

    output = (encrypt_caesar if encrypting else decrypt_caesar)(data)

    set_output(output)


def run_vigenere():
    action = get_action()
    encrypting = action == 'E'
    data = clean_vigenere(get_input(binary=False))

    print("* Transform *")
    keyword = clean_vigenere(input("Keyword? "))

    print("{}crypting {} using Vigenere cipher and keyword {}...".format('En' if encrypting else 'De', data, keyword))

    output = (encrypt_vigenere if encrypting else decrypt_vigenere_with_key)(data, keyword)

    set_output(output)


def run_scytale():
    action = get_action()
    encrypting = action == 'E'
    data = clean_scytale(get_input(binary=False))

    print("* Transform *")
    key = int(input("Key (number of rails): "))

    print("{}crypting {} using Scytale cipher and key {}...".format('En' if encrypting else 'De', data, key))

    output = (encrypt_scytale if encrypting else decrypt_scytale)(data, key)

    set_output(output)


def run_rail_fence():
    action = get_action()
    encrypting = action == 'E'
    data = clean_scytale(get_input(binary=False))

    print("* Transform *")
    num_rails = int(input("Number of rails: "))

    print("{}crypting {} using Rail Fence cipher with {} rails...".format('En' if encrypting else 'De', data, num_rails))

    output = (encrypt_rail_fence if encrypting else decrypt_rail_fence)(data, num_rails)

    set_output(output)


def run_binary_encryption():
    """Encrypt/decrypt binary files (images, audio, etc.)"""
    action = get_action()
    encrypting = action == 'E'
    
    print("* Binary Encryption Options *")
    cipher_choice = _get_selection("(C)aesar or (V)igenere cipher for binary? ", "CV")
    
    print("* Input File *")
    input_filename = get_filename()
    
    with open(input_filename, 'rb') as f:
        data = f.read()
    
    print("* Transform *")
    
    if cipher_choice == 'C':
        # Caesar binary
        shift = int(input("Shift amount (0-255): "))
        print("{}crypting {} using binary Caesar cipher with shift {}...".format(
            'En' if encrypting else 'De', input_filename, shift))
        output = (encrypt_caesar_binary if encrypting else decrypt_caesar_binary)(data, shift)
    else:
        # Vigenere binary
        keyword = input("Keyword: ").strip()
        while not keyword:
            keyword = input("Keyword: ").strip()
        print("{}crypting {} using binary Vigenere cipher with keyword {}...".format(
            'En' if encrypting else 'De', input_filename, keyword))
        output = (encrypt_vigenere_binary if encrypting else decrypt_vigenere_binary)(data, keyword)
    
    # Output
    print("* Output File *")
    output_filename = get_filename()
    with open(output_filename, 'wb') as f:
        f.write(output)
    print("Successfully wrote encrypted data to {}".format(output_filename))


def run_intelligent_codebreaker():
    """Break a Vigenere cipher without knowing the key"""
    print("* Intelligent Vigenere Codebreaker *")
    print("This will attempt to decrypt a Vigenere cipher by trying all possible keys")
    print("from the dictionary and finding the most English-like result.")
    
    print("\n* Ciphertext Input *")
    ciphertext_choice = _get_selection("(F)ile or (S)tring? ", "FS")
    
    if ciphertext_choice == 'S':
        ciphertext = input("Enter ciphertext: ").strip().upper()
        while not ciphertext:
            ciphertext = input("Enter ciphertext: ").strip().upper()
    else:
        filename = get_filename()
        with open(filename, 'r') as f:
            ciphertext = f.read().strip()
    
    print("\n* Possible Keys *")
    print("Loading dictionary words as possible keys...")
    
    # Read possible keys from dictionary
    with open('/usr/share/dict/words', 'r') as f:
        possible_keys = f.read()
    
    # Filter keys (optional - you can customize this)
    filter_keys = get_yes_or_no("Filter keys to common word lengths (3-10 chars)?")
    if filter_keys:
        keys_list = [key.strip() for key in possible_keys.split('\n') 
                     if 3 <= len(key.strip()) <= 10 and key.strip().isalpha()]
        possible_keys = '\n'.join(keys_list)
        print("Filtered to {} possible keys".format(len(keys_list)))
    
    print("\n* Breaking the cipher... *")
    print("This may take a while depending on the number of possible keys...")
    print("(Testing all dictionary words as potential keys)\n")
    
    result = decrypt_vigenere(ciphertext, possible_keys)
    
    print("\n" + "="*50)
    print("* RESULTS *")
    print("="*50)
    print("Best matching key: {}".format(result['key']))
    print("Confidence score: {:.2%}".format(result['score']))
    print("\nDecrypted text:")
    print("-"*50)
    print(result['text'])
    print("-"*50)
    
    # Option to save
    if get_yes_or_no("\nSave decrypted text to file?"):
        filename = get_filename()
        with open(filename, 'w') as f:
            f.write(result['text'])
        print("Saved to {}".format(filename))


def run_merkle_hellman():
    action = get_action()

    print("* Seed *")
    seed = input("Set Seed [enter for random]: ")
    import random
    if not seed:
        random.seed()
    else:
        random.seed(seed)

    print("* Building private key...")

    private_key = generate_private_key()
    public_key = create_public_key(private_key)

    if action == 'E':  # Encrypt
        data = get_input(binary=True)
        print("* Transform *")
        chunks = encrypt_mh(data, public_key)
        output = ' '.join(map(str, chunks))
    else:  # Decrypt
        data = get_input(binary=False)
        chunks = [int(line.strip()) for line in data.split() if line.strip()]
        print("* Transform *")
        output = decrypt_mh(chunks, private_key)

    set_output(output)


def run_suite():
    """
    Runs a single iteration of the cryptography suite.

    Asks the user for input text from a string or file, whether to encrypt
    or decrypt, what tool to use, and where to show the output.
    """
    print('-' * 50)
    tool = get_tool()
    # This isn't the cleanest way to implement functional control flow,
    # but I thought it was too cool to not sneak in here!
    commands = {
        'C': run_caesar,                    # Caesar Cipher
        'V': run_vigenere,                  # Vigenere Cipher
        'M': run_merkle_hellman,            # Merkle-Hellman Knapsack Cryptosystem
        'S': run_scytale,                   # Scytale
        'R': run_rail_fence,                # Rail Fence Cipher
        'B': run_binary_encryption,         # Binary Encryption (files)
        'I': run_intelligent_codebreaker    # Intelligent Vigenere Codebreaker
    }
    commands[tool]()


def main():
    """Harness for CS41 Assignment 1 - Enhanced Edition"""
    print("="*50)
    print("Welcome to the Enhanced Cryptography Suite!")
    print("="*50)
    print("\nFeatures:")
    print("  • Classic text ciphers (Caesar, Vigenere, Scytale)")
    print("  • Rail Fence cipher")
    print("  • Binary file encryption (images, audio, etc.)")
    print("  • Intelligent codebreaker for Vigenere cipher")
    print("  • Merkle-Hellman public key cryptosystem")
    print()
    
    run_suite()
    while get_yes_or_no("Run another encryption/decryption?"):
        run_suite()
    print("\nGoodbye! Stay secure!")


if __name__ == '__main__':
    main()