#!/usr/bin/env python3 -tt
"""
File: crypto.py
---------------
Assignment 1: Cryptography
Course: CS 41
Name: Ferencz Peter
SSID: fpim2346

Replace this with a description of the program.
"""
import utils

# Caesar Cipher

def encrypt_caesar(plaintext):
    """Encrypt plaintext using a Caesar cipher.

    Add more implementation details here.
    """
    encrypted_text = ""
    for letter in plaintext:
        new_letter = chr((ord(letter) - ord('A') + 3) % 26 + ord('A'))
        encrypted_text += new_letter

    return encrypted_text

def decrypt_caesar(ciphertext):
    """Decrypt a ciphertext using a Caesar cipher.

    Add more implementation details here.
    """
    decrypted_text = ""
    for letter in ciphertext:
        new_letter = chr((ord(letter) - ord('A') + 23) % 26 + ord('A'))
        decrypted_text += new_letter

    return decrypted_text


# Vigenere Cipher

def encrypt_vigenere(plaintext, keyword):
    """Encrypt plaintext using a Vigenere cipher with a keyword.
    Only encrypts letters (A-Z, a-z). Preserves spaces, punctuation, and case.
    So later we can use it to brake the encription.:))
    Add more implementation details here.
    """

    encrypted_text = ""
    key_index = 0
    for letter in plaintext:
        if letter.isalpha():
            j = key_index % len(keyword)
            new_letter = chr(( (ord(letter) - ord('A')) + (ord(keyword[j]) - ord('A')) ) % 26 + ord('A'))
            encrypted_text += new_letter
            key_index += 1
        else:
            encrypted_text += letter

    return encrypted_text

    raise NotImplementedError  # Your implementation here


def decrypt_vigenere_with_key(ciphertext, keyword):
    """Decrypt ciphertext using a Vigenere cipher with a keyword.

    Add more implementation details here.
    """

    decrypted_text = ""
    key_index = 0
    
    for letter in ciphertext:
        if letter.isalpha():
            j = key_index % len(keyword)
            new_letter = chr(((ord(letter) - ord('A')) - (ord(keyword[j]) - ord('A')) + 26) % 26 + ord('A'))
            decrypted_text += new_letter
            key_index += 1
        else:
            decrypted_text += letter

    return decrypted_text

def get_words():
    path = "/usr/share/dict/words"
    with open(path, 'r') as f:
        words = f.read()
    
    return words

def score_text(text, word_set):
    """Score how English-y a text is based on valid dictionary words."""
    words_in_text = text.split()
    
    valid_word_count = 0
    for word in words_in_text:
        clean_word = ''.join(c for c in word if c.isalpha())
        if clean_word and clean_word in word_set:
            valid_word_count += 1
    
    total_words = len(words_in_text)
    if total_words == 0:
        return 0
    return valid_word_count / total_words

def decrypt_vigenere(ciphertext, possible_keys):
    """Decrypt ciphertext using a Vigenere cipher without knowing the exact keyword.
    Tries all possible keys and returns the best match based on English dictionary words.
    """
    word_set = get_words()
    
    keys_list = possible_keys.strip().split('\n')
    
    best_score = 0
    best_key = None
    best_text = None

    for key in keys_list:
        key = key.strip().upper()
        if not key:
            continue
            
        decrypted_text = decrypt_vigenere_with_key(ciphertext, key)
        score = score_text(decrypted_text, word_set)
        
        if score > best_score:
            best_score = score
            best_key = key
            best_text = decrypted_text
    
    return {
        "key": best_key,
        "text": best_text,
        "score": best_score
    }


def encrypt_scytale(plaintext, n):
    return ''.join(plaintext[i::n] for i in range(n))

def decrypt_scytale(ciphertext, n):
    m = len(ciphertext)
    cols = (m + n - 1) // n

    rows = []
    start = 0
    for i in range(n):
        end = start + cols
        if end > m:
            end = m
        rows.append(ciphertext[start:end])
        start = end

    return ''.join(row[i] for i in range(cols) for row in rows if i < len(row))


def encrypt_rail_fence(plaintext, num_rails):
    """
    There will be a fance 2D array, in which every row would be a rail.
    Every char will be taken one by one, and with the help of a direction
    variable will be put in the correct rail.
    """
    fence = [[] for _ in range(num_rails)]

    rail = 0
    direction = 1

    for char in plaintext:
        fence[rail].append(char)
        rail += direction
        if rail == 0 or rail == num_rails - 1:
            direction *= -1

    return ''.join(''.join(row) for row in fence)


def decrypt_railfence(ciphertext, num_rails):
    """
    A fence(2D matrix) will be created to which a zig-zag pattern with the help of the '*'
    caracter will be added. Afterwards the fence will be traversed normally, and whenever
    a '*' is found, it will be replaced with the next caracter from the ciphertext. The last
    step is, to traverse the fence once more in the zig-zag pattern.
    """
    fence = [['' for _ in ciphertext] for _ in range(num_rails)]

    rail = 0
    direction = 1
    for i in range(len(ciphertext)):
        fence[rail][i] = '*'
        rail += direction
        if rail == 0 or rail == num_rails - 1:
            direction *= -1

    index = 0
    for r in range(num_rails):
        for c in range(len(ciphertext)):
            if fence[r][c] == '*':
                fence[r][c] = ciphertext[index]
                index += 1

    result = []
    rail, direction = 0, 1
    for i in range(len(ciphertext)):
        result.append(fence[rail][i])
        rail += direction
        if rail == 0 or rail == num_rails - 1:
            direction *= -1

    return ''.join(result)



# Merkle-Hellman Knapsack Cryptosystem

def generate_private_key(n=8):
    """Generate a private key for use in the Merkle-Hellman Knapsack Cryptosystem.

    Following the instructions in the handout, construct the private key components
    of the MH Cryptosystem. This consistutes 3 tasks:

    1. Build a superincreasing sequence `w` of length n
        (Note: you can check if a sequence is superincreasing with `utils.is_superincreasing(seq)`)
    2. Choose some integer `q` greater than the sum of all elements in `w`
    3. Discover an integer `r` between 2 and q that is coprime to `q` (you can use utils.coprime)

    You'll need to use the random module for this function, which has been imported already

    Somehow, you'll have to return all of these values out of this function! Can we do that in Python?!

    @param n bitsize of message to send (default 8)
    @type n int

    @return 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.
    """
    raise NotImplementedError  # Your implementation here

def create_public_key(private_key):
    """Create a public key corresponding to the given private key.

    To accomplish this, you only need to build and return `beta` as described in the handout.

        beta = (b_1, b_2, ..., b_n) where b_i = r × w_i mod q

    Hint: this can be written in one line using a list comprehension

    @param private_key The private key
    @type private_key 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.

    @return n-tuple public key
    """
    raise NotImplementedError  # Your implementation here


def encrypt_mh(message, public_key):
    """Encrypt an outgoing message using a public key.

    1. Separate the message into chunks the size of the public key (in our case, fixed at 8)
    2. For each byte, determine the 8 bits (the `a_i`s) using `utils.byte_to_bits`
    3. Encrypt the 8 message bits by computing
         c = sum of a_i * b_i for i = 1 to n
    4. Return a list of the encrypted ciphertexts for each chunk in the message

    Hint: think about using `zip` at some point

    @param message The message to be encrypted
    @type message bytes
    @param public_key The public key of the desired recipient
    @type public_key n-tuple of ints

    @return list of ints representing encrypted bytes
    """
    raise NotImplementedError  # Your implementation here

def decrypt_mh(message, private_key):
    """Decrypt an incoming message using a private key

    1. Extract w, q, and r from the private key
    2. Compute s, the modular inverse of r mod q, using the
        Extended Euclidean algorithm (implemented at `utils.modinv(r, q)`)
    3. For each byte-sized chunk, compute
         c' = cs (mod q)
    4. Solve the superincreasing subset sum using c' and w to recover the original byte
    5. Reconsitite the encrypted bytes to get the original message back

    @param message Encrypted message chunks
    @type message list of ints
    @param private_key The private key of the recipient
    @type private_key 3-tuple of w, q, and r

    @return bytearray or str of decrypted characters
    """
    raise NotImplementedError  # Your implementation here

