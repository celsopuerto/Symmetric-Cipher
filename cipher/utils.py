#CASECAR CIPHER
def perform_caesar_cipher_encryption(plaintext, shift):
    encrypted_text = ""
    
    for char in plaintext:
        if char.isalpha():  # Check if character is an alphabet
            # Determine if it's uppercase or lowercase
            start = ord('A') if char.isupper() else ord('a')
            # Encrypt the character and handle wrapping with modulo 26
            encrypted_char = chr(start + (ord(char) - start + shift) % 26)
            encrypted_text += encrypted_char
        else:
            # If it's not an alphabet, just add it to the result
            encrypted_text += char
    
    return encrypted_text

def perform_caesar_cipher_decryption(ciphertext, shift):
    decrypted_text = ""
    
    for char in ciphertext:
        if char.isalpha():  # Check if character is an alphabet
            # Determine if it's uppercase or lowercase
            start = ord('A') if char.isupper() else ord('a')
            # Decrypt the character and handle wrapping with modulo 26
            decrypted_char = chr(start + (ord(char) - start - shift) % 26)
            decrypted_text += decrypted_char
        else:
            # If it's not an alphabet, just add it to the result
            decrypted_text += char
    
    return decrypted_text