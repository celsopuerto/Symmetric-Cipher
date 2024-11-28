import math
from django.utils.html import escape
# CAESAR CIPHER

def perform_caesarcipher_encryp_decrypt(text, key, mode):
    encrypted_text = ""
    steps_html = ""  # To store the steps of encryption in HTML format

    if mode == "encrypt":
        for i, char in enumerate(text):
            if char.isalpha():  # Check if character is an alphabet
                # Determine if it's uppercase or lowercase
                start = ord('A') if char.isupper() else ord('a')
                position = ord(char) - start  # P (Plaintext position)
                cipher_code = (position + key) % 26  # C = (P + K) % 26
                encrypted_char = chr(cipher_code + start)  # Convert to encrypted character
                encrypted_text += encrypted_char

                # Add step-by-step explanation in HTML
                steps_html += f"<p><b>Step {i + 1}:</b> Encrypt '{escape(char)}'</p>"
                steps_html += f"<p>&nbsp;&nbsp;C = (P + K) mod 26</p>"
                steps_html += f"<p>&nbsp;&nbsp;C = ({position} + {key}) mod 26</p>"
                steps_html += f"<p>&nbsp;&nbsp;C = {position + key} / 26</p>"
                steps_html += f"<p>&nbsp;&nbsp;C = {cipher_code} -> '{escape(encrypted_char)}'</p>"
            else:
                encrypted_text += char
                steps_html += f"<p><b>Step {i + 1}:</b> Non-alphabetic character, no change</p>"

        return encrypted_text, steps_html
    else:
        decrypted_text = ""
        steps_html = ""  # To store the steps of decryption in HTML format

        for i, char in enumerate(text):
            if char.isalpha():  # Check if character is an alphabet
                # Determine if it's uppercase or lowercase
                start = ord('A') if char.isupper() else ord('a')
                position = ord(char) - start  # C (Ciphertext position)
                plain_code = (position - key) % 26  # P = (C - K) % 26
                decrypted_char = chr(plain_code + start)  # Convert to decrypted character
                decrypted_text += decrypted_char

                # Add step-by-step explanation in HTML
                steps_html += f"<p><b>Step {i + 1}:</b> Decrypt '{escape(char)}'</p>"
                steps_html += f"<p>&nbsp;&nbsp;P = (C - K) mod 26</p>"
                steps_html += f"<p>&nbsp;&nbsp;P = ({position} - {key}) mod 26</p>"
                steps_html += f"<p>&nbsp;&nbsp;P = {position - key} / 26</p>"
                steps_html += f"<p>&nbsp;&nbsp;P = {plain_code} -> '{escape(decrypted_char)}'</p>"
            else:
                decrypted_text += char
                steps_html += f"<p><b>Step {i + 1}:</b> Non-alphabetic character, no change</p>"

        return decrypted_text, steps_html


#VIGENERE CIPHER


#PLAYFAIR CIPHER
def generate_matrix(key):
    key = key.upper().replace("J", "I")
    matrix = []
    seen = set()

    # Add characters from the key to the matrix (no duplicates)
    for char in key:
        if char not in seen and char.isalpha():
            matrix.append(char)
            seen.add(char)

    # Add remaining letters of the alphabet to the matrix
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # Note: 'J' is excluded
    for char in alphabet:
        if char not in seen:
            matrix.append(char)

    # Return the matrix as a list of lists (5x5 grid)
    return [matrix[i:i + 5] for i in range(0, 25, 5)]

def prepare_text(text):
    text = text.upper().replace("J", "I")
    text = ''.join([char for char in text if char.isalpha()])

    if len(text) % 2 != 0:
        text += "X"

    digraphs = []
    i = 0
    while i < len(text):
        if i + 1 < len(text) and text[i] == text[i + 1]:
            digraphs.append(text[i] + 'X')
            i += 1
        else:
            digraphs.append(text[i:i + 2])
            i += 2

    return digraphs

def find_position(matrix, char):
    for i, row in enumerate(matrix):
        if char in row:
            return i, row.index(char)
    raise ValueError(f"Character {char} not found in matrix")

def playfair_encrypt_decrypt(matrix, digraph, mode='encrypt'):
    try:
        row1, col1 = find_position(matrix, digraph[0])
        row2, col2 = find_position(matrix, digraph[1])
    except ValueError as e:
        raise e

    if row1 == row2:
        if mode == 'encrypt':
            col1 = (col1 + 1) % 5
            col2 = (col2 + 1) % 5
        else:
            col1 = (col1 - 1) % 5
            col2 = (col2 - 1) % 5
    elif col1 == col2:
        if mode == 'encrypt':
            row1 = (row1 + 1) % 5
            row2 = (row2 + 1) % 5
        else:
            row1 = (row1 - 1) % 5
            row2 = (row2 - 1) % 5
    else:
        col1, col2 = col2, col1

    return matrix[row1][col1] + matrix[row2][col2]

def perform_playfair_cipher(key, text, mode):
    matrix = generate_matrix(key)
    digraphs = prepare_text(text)
    result = ''
    solution_steps_html = f"<h3>Playfair Cipher Solution for '{text}'</h3>"

    # Display the matrix in a column-wise format
    solution_steps_html += f"<h3><b>Matrix:</b><pre>"
    for row in matrix:
        solution_steps_html += " ".join(row) + "\n"  # Stack each row on top of each other
    solution_steps_html += "</pre></h3>"

    for i, digraph in enumerate(digraphs):
        solution_steps_html += f"<p><b>Step {i + 1}:</b> Encrypting/Decrypting Digraph: '{escape(digraph)}'</p>"

        try:
            result += playfair_encrypt_decrypt(matrix, digraph, mode)
            solution_steps_html += f"<p>&nbsp;&nbsp;Resulting Pair: '{escape(result[-2:])}'</p>"
        except Exception as e:
            solution_steps_html += f"<p>Error encrypting/decrypting digraph {escape(digraph)}: {e}</p>"

    return result, solution_steps_html


#SINGLE COLUMNAR
def single_columnar_cipher(text, keyword, mode):
    steps = []  # Collect steps for display
    grids = []  # Collect grids for visualization
    decrypted_str = []

    if mode == 'encrypt':
        steps.append("Starting Encryption Process... <br>")
        text = text.replace(" ", "_").upper()
        keyword = keyword.upper()
        steps.append(f"Text after replacing spaces with underscores: {text} <br>")
        steps.append(f"Keyword: {keyword} <br>")
        
        key_len = len(keyword)
        num_rows = (len(text) + key_len - 1) // key_len  # Ceiling division
        
        padding = '_' * (num_rows * key_len - len(text))
        text += padding
        steps.append(f"Padded text: {text} <br>")
        
        grid = [['' for _ in range(key_len)] for _ in range(num_rows)]
        k = 0
        for i in range(num_rows):
            for j in range(key_len):
                grid[i][j] = text[k]
                k += 1
        grids.append(grid)  # Add the grid for visualization
        steps.append("Grid created with padded text. <br>")
        
        sorted_keyword = sorted((char, idx) for idx, char in enumerate(keyword))
        column_order = [idx for char, idx in sorted_keyword]
        
        ciphertext = ""
        for idx in column_order:
            col_data = "".join(row[idx] for row in grid)
            steps.append(f"Reading Column {idx + 1} (Keyword: '{keyword[idx]}'): {col_data} <br>")
            ciphertext += col_data
        
        steps.append(f"Final Ciphertext: {ciphertext}")
        steps_str = ''.join(steps)
        return ciphertext, steps_str, grids, decrypted_str
    else:
        steps.append("Starting Decryption Process... <br>")
        keyword = keyword.upper()
        steps.append(f"Keyword: {keyword} <br>")
        
        key_len = len(keyword)
        num_rows = (len(text) + key_len - 1) // key_len
        
        padding = '_' * (num_rows * key_len - len(text))
        text += padding
        steps.append(f"Padded ciphertext: {text} <br>")
        
        grid = [['' for _ in range(key_len)] for _ in range(num_rows)]
        
        sorted_keyword = sorted((char, idx) for idx, char in enumerate(keyword))
        column_order = [idx for char, idx in sorted_keyword]
        
        k = 0
        for idx in column_order:
            for i in range(num_rows):
                grid[i][idx] = text[k]
                k += 1
        grids.append(grid)  # Add the grid for visualization
        steps.append("Grid filled column-wise based on sorted keyword. <br>")
        
        decrypted_str = "".join("".join(row) for row in grid)
        plaintext = "".join("".join(row) for row in grid).rstrip('_').replace("_", " ")
        steps.append(f"Final Decrypted Text: {plaintext} <br>")
        steps_str = ''.join(steps)
        return plaintext, steps_str, grids, decrypted_str


#DOUBLE COLUMNAR
def perform_double_columnar_cipher(text, keyword, mode):
    steps = []  # Collect steps for display
    grids = []  # Collect grids for visualization
    decrypted_str = ""

    if mode == 'encrypt':
        steps.append("Starting Encryption Process... <br>")
        text = text.replace(" ", "_").upper()
        keyword = keyword.upper()
        steps.append(f"Text after replacing spaces with underscores: {text} <br>")
        steps.append(f"Keyword: {keyword} <br>")
        
        key_len = len(keyword)
        num_rows = (len(text) + key_len - 1) // key_len  # Ceiling division
        
        padding = '_' * (num_rows * key_len - len(text))
        text += padding
        steps.append(f"Padded text: {text} <br>")
        
        grid = [['' for _ in range(key_len)] for _ in range(num_rows)]
        k = 0
        for i in range(num_rows):
            for j in range(key_len):
                grid[i][j] = text[k]
                k += 1
        grids.append(grid)  # Add the grid for visualization
        steps.append("Grid created with padded text. <br>")
        
        sorted_keyword = sorted((char, idx) for idx, char in enumerate(keyword))
        column_order = [idx for char, idx in sorted_keyword]
        
        ciphertext = ""
        for idx in column_order:
            col_data = "".join(row[idx] for row in grid)
            steps.append(f"Reading Column {idx + 1} (Keyword: '{keyword[idx]}'): {col_data} <br>")
            ciphertext += col_data
        
        steps.append(f"Final Ciphertext: {ciphertext}")
        steps_str = ''.join(steps)
        return ciphertext, steps_str, grids, decrypted_str
    else:
        steps.append("Starting Decryption Process... <br>")
        keyword = keyword.upper()
        steps.append(f"Keyword: {keyword} <br>")
        
        key_len = len(keyword)
        num_rows = (len(text) + key_len - 1) // key_len
        
        padding = '_' * (num_rows * key_len - len(text))
        text += padding
        steps.append(f"Padded ciphertext: {text} <br>")
        
        grid = [['' for _ in range(key_len)] for _ in range(num_rows)]
        
        sorted_keyword = sorted((char, idx) for idx, char in enumerate(keyword))
        column_order = [idx for char, idx in sorted_keyword]
        
        k = 0
        for idx in column_order:
            for i in range(num_rows):
                grid[i][idx] = text[k]
                k += 1
        grids.append(grid)  # Add the grid for visualization
        steps.append("Grid filled column-wise based on sorted keyword. <br>")
        
        # In the decryption process, do NOT remove underscores
        decrypted_str = "".join("".join(row) for row in grid)
        
        steps.append(f"Final Decrypted Text with padding: {decrypted_str} <br>")
        steps_str = ''.join(steps)
        return decrypted_str, steps_str, grids, decrypted_str


def double_columnar_cipher(text, key, key2, mode):
    steps = []  # Collect steps for display
    if mode == 'encrypt':
        
        first_pass, steps_str, grids, decrypted_str = perform_double_columnar_cipher(text, key, mode)
        
        second_pass, steps_str2, grids2, decrypted_str = perform_double_columnar_cipher(first_pass, key2, mode)

        # Join the steps list into a single string for display
        print(text)
        print(first_pass)
        print(second_pass)
        return second_pass, steps_str, steps_str2, grids, grids2, decrypted_str
    else:

        first_pass, steps_str, grids, decrypted_str = perform_double_columnar_cipher(text, key2, mode)

        second_pass, steps_str2, grids2, decrypted_str = perform_double_columnar_cipher(first_pass, key, mode)

        print(text)
        print(first_pass)
        print(second_pass)
        return second_pass, steps_str, steps_str2, grids, grids2, decrypted_str
    
    
# ADVANCED ENCRYPTION STANDARD
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
from base64 import b64encode, b64decode
from hashlib import sha256

class PerformAESCipher:
    def __init__(self, key: bytes):
        """
        Initialize the AES cipher with a key. The key must be 16, 24, or 32 bytes long.
        If the provided key is not of a valid size, it will be hashed to derive a 32-byte key.
        """
        if len(key) not in (16, 24, 32):
            key = sha256(key).digest()  # Derive a 32-byte key from the given key
        self.key = key
        self.backend = default_backend()

    def encrypt(self, data: str) -> str:
        """
        Encrypts the given string data using AES encryption in CBC mode.
        Returns a base64-encoded string of the encrypted data (IV + ciphertext).
        """
        data_bytes = data.encode('utf-8')

        # Pad the data to make it a multiple of the block size (16 bytes for AES)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data_bytes) + padder.finalize()

        # Generate a random IV (Initialization Vector)
        iv = os.urandom(16)

        # Create a Cipher object with the key and IV
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        # Encrypt the padded data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Return the IV and encrypted data as a base64-encoded string
        return b64encode(iv + encrypted_data).decode('utf-8')

    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypts a base64-encoded string of encrypted data (IV + ciphertext).
        Returns the original plaintext string.
        """
        try:
            encrypted_data_bytes = b64decode(encrypted_data)

            # Extract the IV and encrypted data
            iv = encrypted_data_bytes[:16]
            ciphertext = encrypted_data_bytes[16:]

            # Create a Cipher object with the key and IV
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()

            # Decrypt the data
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

            # Remove the padding from the decrypted data
            unpadder = padding.PKCS7(128).unpadder()
            data_bytes = unpadder.update(decrypted_data) + unpadder.finalize()

            # Return the original plaintext string
            return data_bytes.decode('utf-8')
        except Exception as e:
            # Raise a specific error for debugging purposes
            raise ValueError(f"Decryption failed: {str(e)}")