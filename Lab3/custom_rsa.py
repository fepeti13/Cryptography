import random

def miller_rabin(n, k=40):
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y

def mod_inverse(a, m):
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % m + m) % m

def generate_prime(bits):
    print(f"[RSA]: Generating {bits}-bit prime...")
    attempts = 0
    while True:
        attempts += 1
        num = random.randrange(2**(bits-1), 2**bits) | 1
        
        if miller_rabin(num):
            print(f"[RSA]: Prime found after {attempts} attempts")
            return num

def check_goodness(p, q):
    print("[RSA]: Checking goodness criteria...")
    
    if p == q:
        print("[RSA]: not Passed p = q")
        return False
    print("[RSA]: Passed p != q")
    
    diff = abs(p - q)
    if diff < 2**400:
        print("[RSA]: Not Passed |p - q| too small")
        return False
    print(f"[RSA]: Passed |p - q| = {diff.bit_length()} bits")
    
    g = gcd(p - 1, q - 1)
    if g > 2**16:
        print(f"[RSA]: Not Passed gcd(p-1, q-1) = {g} too large")
        return False
    print(f"[RSA]: Passed gcd(p-1, q-1) = {g}")
    
    p_factor = (p - 1) // 2
    q_factor = (q - 1) // 2
    while p_factor % 2 == 0:
        p_factor //= 2
    while q_factor % 2 == 0:
        q_factor //= 2
    
    if p_factor.bit_length() < 256 or q_factor.bit_length() < 256:
        print("[RSA]: Factors too small")
        return False
    print(f"[RSA]: Large factors ({p_factor.bit_length()}, {q_factor.bit_length()} bits)")
    
    print("[RSA]: All criteria passed!")
    return True

def generate_keypair():
    print("[RSA]: Generating RSA-2048 keypair (custom implementation)...")
    
    while True:
        p = generate_prime(1024)
        q = generate_prime(1024)
        
        if check_goodness(p, q):
            break
        print("[RSA]: Regenerating primes...")
    
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)
    
    print(f"[RSA]: Keypair generated (n = {n.bit_length()} bits)")
    return p, q, n, e, d

def encrypt_bytes(data, e, n):
    block_size = 256
    if len(data) > block_size - 11:
        raise ValueError("Data too large")
    
    padding_len = block_size - len(data) - 3
    padding = bytes([random.randint(1, 255) for _ in range(padding_len)])
    padded = b'\x00\x02' + padding + b'\x00' + data
    
    m = int.from_bytes(padded, 'big')
    c = pow(m, e, n)
    return c.to_bytes(block_size, 'big')

def decrypt_bytes(data, d, n):
    c = int.from_bytes(data, 'big')
    m = pow(c, d, n)
    padded = m.to_bytes(256, 'big')
    
    sep = padded.find(b'\x00', 2)
    return padded[sep + 1:]

def export_public_key(e, n):
    return f"{e}:{n}"

def import_public_key(key_str):
    e, n = key_str.split(':')
    return int(e), int(n)

if __name__ == "__main__":
    print("Testing Custom RSA-2048\n")
    p, q, n, e, d = generate_keypair()
    
    msg = b"Hello Hello"
    encrypted = encrypt_bytes(msg, e, n)
    decrypted = decrypt_bytes(encrypted, d, n)
    print(f"\nOriginal: {msg}")
    print(f"Decrypted: {decrypted}")
    print(f"Success: {msg == decrypted}")