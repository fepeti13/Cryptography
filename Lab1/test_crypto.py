#!/usr/bin/env python3 -tt
"""
File: test_crypto.py
--------------------
Comprehensive test suite for all cryptography functions.
Tests encryption/decryption with various inputs to ensure correctness.

Run with: python3 test_crypto.py
"""

from crypto import (
    encrypt_caesar, decrypt_caesar,
    encrypt_caesar_binary, decrypt_caesar_binary,
    encrypt_vigenere, decrypt_vigenere_with_key,
    encrypt_vigenere_binary, decrypt_vigenere_binary,
    encrypt_scytale, decrypt_scytale,
    encrypt_rail_fence, decrypt_rail_fence,
    get_words, score_text, decrypt_vigenere
)


def test_caesar_cipher():
    """Test Caesar cipher encryption and decryption"""
    print("Testing Caesar Cipher...")
    
    # Test 1: Basic encryption
    plaintext = "HELLO"
    ciphertext = encrypt_caesar(plaintext)
    assert ciphertext == "KHOOR", f"Expected 'KHOOR', got '{ciphertext}'"
    
    # Test 2: Basic decryption
    decrypted = decrypt_caesar(ciphertext)
    assert decrypted == plaintext, f"Expected '{plaintext}', got '{decrypted}'"
    
    # Test 3: Full alphabet
    plaintext = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ciphertext = encrypt_caesar(plaintext)
    decrypted = decrypt_caesar(ciphertext)
    assert decrypted == plaintext, f"Full alphabet test failed"
    
    # Test 4: Wrap around (XYZ -> ABC)
    plaintext = "XYZ"
    ciphertext = encrypt_caesar(plaintext)
    assert ciphertext == "ABC", f"Expected 'ABC', got '{ciphertext}'"
    
    # Test 5: Empty string
    assert encrypt_caesar("") == "", "Empty string test failed"
    assert decrypt_caesar("") == "", "Empty string decryption failed"
    
    print("✓ Caesar Cipher tests passed!")


def test_caesar_binary():
    """Test Caesar cipher on binary data"""
    print("Testing Caesar Binary Cipher...")
    
    # Test 1: Basic binary data
    data = b"HELLO WORLD"
    shift = 42
    encrypted = encrypt_caesar_binary(data, shift)
    decrypted = decrypt_caesar_binary(encrypted, shift)
    assert decrypted == data, f"Binary Caesar roundtrip failed"
    
    # Test 2: All possible byte values
    data = bytes(range(256))
    shift = 100
    encrypted = encrypt_caesar_binary(data, shift)
    decrypted = decrypt_caesar_binary(encrypted, shift)
    assert decrypted == data, f"Full byte range test failed"
    
    # Test 3: Empty data
    assert encrypt_caesar_binary(b"", 10) == b"", "Empty binary test failed"
    
    # Test 4: Shift of 0
    data = b"TEST"
    encrypted = encrypt_caesar_binary(data, 0)
    assert encrypted == data, "Shift 0 should not change data"
    
    # Test 5: Different shifts
    data = b"ABC"
    for shift in [1, 5, 10, 50, 100, 255]:
        encrypted = encrypt_caesar_binary(data, shift)
        decrypted = decrypt_caesar_binary(encrypted, shift)
        assert decrypted == data, f"Shift {shift} roundtrip failed"
    
    print("✓ Caesar Binary Cipher tests passed!")


def test_vigenere_cipher():
    """Test Vigenere cipher encryption and decryption"""
    print("Testing Vigenere Cipher...")
    
    # Test 1: Basic encryption/decryption
    plaintext = "HELLO"
    keyword = "KEY"
    ciphertext = encrypt_vigenere(plaintext, keyword)
    decrypted = decrypt_vigenere_with_key(ciphertext, keyword)
    assert decrypted == plaintext, f"Basic Vigenere test failed: expected '{plaintext}', got '{decrypted}'"
    
    # Test 2: Longer text
    plaintext = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
    keyword = "SECRET"
    ciphertext = encrypt_vigenere(plaintext, keyword)
    decrypted = decrypt_vigenere_with_key(ciphertext, keyword)
    assert decrypted == plaintext, f"Long text test failed"
    
    # Test 3: With spaces and punctuation
    plaintext = "HELLO WORLD!"
    keyword = "KEY"
    ciphertext = encrypt_vigenere(plaintext, keyword)
    decrypted = decrypt_vigenere_with_key(ciphertext, keyword)
    assert decrypted == plaintext, f"Spaces/punctuation test failed"
    assert " " in ciphertext, "Spaces should be preserved"
    assert "!" in ciphertext, "Punctuation should be preserved"
    
    # Test 4: Single character key
    plaintext = "HELLO"
    keyword = "A"  # Should be like Caesar with shift 0
    ciphertext = encrypt_vigenere(plaintext, keyword)
    assert ciphertext == plaintext, f"Key 'A' should not change text"
    
    # Test 5: Key longer than text
    plaintext = "HI"
    keyword = "LONGKEYWORD"
    ciphertext = encrypt_vigenere(plaintext, keyword)
    decrypted = decrypt_vigenere_with_key(ciphertext, keyword)
    assert decrypted == plaintext, f"Long key test failed"
    
    # Test 6: Same character repeated
    plaintext = "AAAA"
    keyword = "B"
    ciphertext = encrypt_vigenere(plaintext, keyword)
    assert ciphertext == "BBBB", f"Expected 'BBBB', got '{ciphertext}'"
    
    print("✓ Vigenere Cipher tests passed!")


def test_vigenere_binary():
    """Test Vigenere cipher on binary data"""
    print("Testing Vigenere Binary Cipher...")
    
    # Test 1: Basic binary encryption/decryption
    data = b"HELLO WORLD"
    key = "SECRET"
    encrypted = encrypt_vigenere_binary(data, key)
    decrypted = decrypt_vigenere_binary(encrypted, key)
    assert decrypted == data, f"Binary Vigenere roundtrip failed"
    
    # Test 2: Binary data with all byte values
    data = bytes(range(256))
    key = "KEY"
    encrypted = encrypt_vigenere_binary(data, key)
    decrypted = decrypt_vigenere_binary(encrypted, key)
    assert decrypted == data, f"Full byte range test failed"
    
    # Test 3: Key as bytes
    data = b"TEST"
    key = b"KEY"
    encrypted = encrypt_vigenere_binary(data, key)
    decrypted = decrypt_vigenere_binary(encrypted, key)
    assert decrypted == data, f"Bytes key test failed"
    
    # Test 4: Empty data
    assert encrypt_vigenere_binary(b"", "KEY") == b"", "Empty data test failed"
    
    # Test 5: Different key lengths
    data = b"ABCDEFGHIJKLMNOP"
    for key in ["A", "AB", "ABC", "ABCDEFGH"]:
        encrypted = encrypt_vigenere_binary(data, key)
        decrypted = decrypt_vigenere_binary(encrypted, key)
        assert decrypted == data, f"Key length {len(key)} test failed"
    
    print("✓ Vigenere Binary Cipher tests passed!")


def test_scytale_cipher():
    """Test Scytale cipher encryption and decryption"""
    print("Testing Scytale Cipher...")
    
    # Test 1: Basic encryption/decryption
    plaintext = "HELLOWORLD"
    n = 3
    ciphertext = encrypt_scytale(plaintext, n)
    decrypted = decrypt_scytale(ciphertext, n)
    assert decrypted == plaintext, f"Basic Scytale test failed: expected '{plaintext}', got '{decrypted}'"
    
    # Test 2: Different rail counts
    plaintext = "THEQUICKBROWNFOX"
    for n in [2, 3, 4, 5]:
        ciphertext = encrypt_scytale(plaintext, n)
        decrypted = decrypt_scytale(ciphertext, n)
        assert decrypted == plaintext, f"Scytale with n={n} failed"
    
    # Test 3: Single rail (no change)
    plaintext = "HELLO"
    n = 1
    ciphertext = encrypt_scytale(plaintext, n)
    assert ciphertext == plaintext, f"Single rail should not change text"
    
    # Test 4: Rails equal to text length
    plaintext = "ABCDE"
    n = 5
    ciphertext = encrypt_scytale(plaintext, n)
    decrypted = decrypt_scytale(ciphertext, n)
    assert decrypted == plaintext, f"Rails=length test failed"
    
    # Test 5: Short text
    plaintext = "AB"
    n = 2
    ciphertext = encrypt_scytale(plaintext, n)
    decrypted = decrypt_scytale(ciphertext, n)
    assert decrypted == plaintext, f"Short text test failed"
    
    print("✓ Scytale Cipher tests passed!")


def test_rail_fence_cipher():
    """Test Rail Fence cipher encryption and decryption"""
    print("Testing Rail Fence Cipher...")
    
    # Test 1: Basic encryption/decryption
    plaintext = "HELLOWORLD"
    num_rails = 3
    ciphertext = encrypt_rail_fence(plaintext, num_rails)
    decrypted = decrypt_rail_fence(ciphertext, num_rails)
    assert decrypted == plaintext, f"Basic Rail Fence test failed: expected '{plaintext}', got '{decrypted}'"
    
    # Test 2: Different rail counts
    plaintext = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
    for num_rails in [2, 3, 4, 5, 6]:
        ciphertext = encrypt_rail_fence(plaintext, num_rails)
        decrypted = decrypt_rail_fence(ciphertext, num_rails)
        assert decrypted == plaintext, f"Rail Fence with {num_rails} rails failed"
    
    # Test 3: Two rails (simple case)
    plaintext = "ABCDEF"
    num_rails = 2
    ciphertext = encrypt_rail_fence(plaintext, num_rails)
    # Pattern: A C E (rail 0) + B D F (rail 1) = ACEBDF
    assert ciphertext == "ACEBDF", f"Expected 'ACEBDF', got '{ciphertext}'"
    decrypted = decrypt_rail_fence(ciphertext, num_rails)
    assert decrypted == plaintext, f"Two rails decryption failed"
    
    # Test 4: Three rails example
    plaintext = "WEAREDISCOVEREDFLEEATONCE"
    num_rails = 3
    ciphertext = encrypt_rail_fence(plaintext, num_rails)
    decrypted = decrypt_rail_fence(ciphertext, num_rails)
    assert decrypted == plaintext, f"Classic Rail Fence example failed"
    
    # Test 5: Single rail
    plaintext = "HELLO"
    num_rails = 1
    ciphertext = encrypt_rail_fence(plaintext, num_rails)
    assert ciphertext == plaintext, f"Single rail should not change text"
    
    print("✓ Rail Fence Cipher tests passed!")


def test_score_text():
    """Test the English text scoring function"""
    print("Testing Text Scoring...")
    
    # Load word set
    word_set = get_words()
    
    # Test 1: All valid English words
    text = "THE QUICK BROWN FOX"
    score = score_text(text, word_set)
    assert score == 1.0, f"All valid words should score 1.0, got {score}"
    
    # Test 2: Some valid words
    text = "HELLO XYZABC WORLD"
    score = score_text(text, word_set)
    assert 0 < score < 1, f"Mixed text should score between 0 and 1, got {score}"
    
    # Test 3: No valid words
    text = "XYZABC QWERTY ASDFGH"
    score = score_text(text, word_set)
    assert score < 0.5, f"Invalid words should score low, got {score}"
    
    # Test 4: Empty text
    score = score_text("", word_set)
    assert score == 0, f"Empty text should score 0, got {score}"
    
    # Test 5: With punctuation
    text = "HELLO, WORLD!"
    score = score_text(text, word_set)
    assert score == 1.0, f"Punctuation should be ignored, got {score}"
    
    print("✓ Text Scoring tests passed!")


def test_decrypt_vigenere_intelligent():
    """Test intelligent Vigenere decryption (codebreaker)"""
    print("Testing Intelligent Vigenere Codebreaker...")
    
    # Test 1: Simple known plaintext
    plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
    keyword = "SECRET"
    ciphertext = encrypt_vigenere(plaintext, keyword)
    
    # Create a small set of possible keys including the correct one
    possible_keys = "KEY\nPASSWORD\nSECRET\nTEST\nHELLO"
    
    result = decrypt_vigenere(ciphertext, possible_keys)
    
    assert result['key'] == keyword, f"Should find correct key 'SECRET', got '{result['key']}'"
    assert result['text'] == plaintext, f"Should decrypt to original plaintext"
    assert result['score'] > 0.8, f"Score should be high for correct decryption, got {result['score']}"
    
    # Test 2: Verify it returns the best match
    plaintext = "HELLO WORLD"
    keyword = "KEY"
    ciphertext = encrypt_vigenere(plaintext, keyword)
    possible_keys = "WRONG\nKEY\nBAD"
    
    result = decrypt_vigenere(ciphertext, possible_keys)
    assert result['key'] == "KEY", f"Should find 'KEY', got '{result['key']}'"
    
    print("✓ Intelligent Vigenere Codebreaker tests passed!")


def test_edge_cases():
    """Test edge cases and error conditions"""
    print("Testing Edge Cases...")
    
    # Test 1: Empty strings
    assert encrypt_caesar("") == ""
    assert decrypt_caesar("") == ""
    assert encrypt_vigenere("", "KEY") == ""
    assert decrypt_vigenere_with_key("", "KEY") == ""
    
    # Test 2: Single character
    assert encrypt_caesar("A") == "D"
    assert decrypt_caesar("D") == "A"
    
    # Test 3: Very long text (no spaces for Caesar)
    long_text = "A" * 10000
    encrypted = encrypt_caesar(long_text)
    decrypted = decrypt_caesar(encrypted)
    assert decrypted == long_text, "Long text test failed"
    
    # Test 4: Vigenere with single letter key
    plaintext = "HELLO"
    encrypted = encrypt_vigenere(plaintext, "A")
    assert encrypted == plaintext, "Key 'A' should not change plaintext"
    
    # Test 5: Binary with large file simulation
    large_data = bytes(range(256)) * 100  # 25.6 KB
    encrypted = encrypt_caesar_binary(large_data, 42)
    decrypted = decrypt_caesar_binary(encrypted, 42)
    assert decrypted == large_data, "Large binary data test failed"
    
    print("✓ Edge Cases tests passed!")


def test_roundtrip_consistency():
    """Test that encrypt->decrypt returns original for all ciphers"""
    print("Testing Roundtrip Consistency...")
    
    test_texts = [
        "HELLO",
        "THEQUICKBROWNFOX",  # Removed spaces - Caesar doesn't handle them
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "A",
        "AB",
        "ABCDEFGHIJKL",  # Removed spaces
        "TESTINGONETWOTHREE"  # Removed spaces and punctuation
    ]
    
    # Caesar
    for text in test_texts:
        encrypted = encrypt_caesar(text)
        decrypted = decrypt_caesar(encrypted)
        assert decrypted == text, f"Caesar roundtrip failed for '{text}'"
    
    # Vigenere
    for text in test_texts:
        for key in ["KEY", "SECRET", "A", "LONGERKEYWORD"]:
            encrypted = encrypt_vigenere(text, key)
            decrypted = decrypt_vigenere_with_key(encrypted, key)
            assert decrypted == text, f"Vigenere roundtrip failed for '{text}' with key '{key}'"
    
    # Scytale
    for text in ["HELLO", "ABCDEFGHIJ", "THEQUICKBROWNFOX"]:
        for n in [2, 3, 4, 5]:
            encrypted = encrypt_scytale(text, n)
            decrypted = decrypt_scytale(encrypted, n)
            assert decrypted == text, f"Scytale roundtrip failed for '{text}' with n={n}"
    
    # Rail Fence
    for text in ["HELLO", "ABCDEFGHIJ", "THEQUICKBROWNFOX"]:
        for rails in [2, 3, 4, 5]:
            encrypted = encrypt_rail_fence(text, rails)
            decrypted = decrypt_rail_fence(encrypted, rails)
            assert decrypted == text, f"Rail Fence roundtrip failed for '{text}' with {rails} rails"
    
    print("✓ Roundtrip Consistency tests passed!")


def run_all_tests():
    """Run all test suites"""
    print("="*60)
    print("CRYPTOGRAPHY TEST SUITE")
    print("="*60)
    print()
    
    test_functions = [
        test_caesar_cipher,
        test_caesar_binary,
        test_vigenere_cipher,
        test_vigenere_binary,
        test_scytale_cipher,
        test_rail_fence_cipher,
        test_score_text,
        test_decrypt_vigenere_intelligent,
        test_edge_cases,
        test_roundtrip_consistency
    ]
    
    passed = 0
    failed = 0
    
    for test_func in test_functions:
        try:
            test_func()
            passed += 1
            print()
        except AssertionError as e:
            print(f"✗ {test_func.__name__} FAILED: {e}")
            failed += 1
            print()
        except Exception as e:
            print(f"✗ {test_func.__name__} ERROR: {e}")
            failed += 1
            print()
    
    print("="*60)
    print(f"TEST RESULTS: {passed} passed, {failed} failed")
    print("="*60)
    
    if failed == 0:
        print("ALL TESTS PASSED!")
        return True
    else:
        print(f"{failed} test(s) failed")
        return False


if __name__ == '__main__':
    success = run_all_tests()
    exit(0 if success else 1)