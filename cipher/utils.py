import math
from django.utils.html import escape

# AES imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hmac
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os

# CAESAR CIPHER


def perform_caesarcipher_encryp_decrypt(text, key, mode):
    encrypted_text = ""
    steps_html = ""  # To store the steps of encryption in HTML format

    if mode == "encrypt":
        for i, char in enumerate(text):
            if char.isalpha():  # Check if character is an alphabet
                # Determine if it's uppercase or lowercase
                start = ord("A") if char.isupper() else ord("a")
                position = ord(char) - start  # P (Plaintext position)
                cipher_code = (position + key) % 26  # C = (P + K) % 26
                encrypted_char = chr(
                    cipher_code + start
                )  # Convert to encrypted character
                encrypted_text += encrypted_char

                # Add step-by-step explanation in HTML
                steps_html += f"<p><b>Step {i + 1}:</b> Encrypt '{escape(char)}'</p>"
                steps_html += f"<p>&nbsp;&nbsp;C = (P + K) mod 26</p>"
                steps_html += f"<p>&nbsp;&nbsp;C = ({position} + {key}) mod 26</p>"
                steps_html += f"<p>&nbsp;&nbsp;C = {position + key} / 26</p>"
                steps_html += f"<p>&nbsp;&nbsp;C = {cipher_code} -> '{escape(encrypted_char)}'</p>"
            else:
                encrypted_text += char
                steps_html += (
                    f"<p><b>Step {i + 1}:</b> Non-alphabetic character, no change</p>"
                )

        return encrypted_text, steps_html
    else:
        decrypted_text = ""
        steps_html = ""  # To store the steps of decryption in HTML format

        for i, char in enumerate(text):
            if char.isalpha():  # Check if character is an alphabet
                # Determine if it's uppercase or lowercase
                start = ord("A") if char.isupper() else ord("a")
                position = ord(char) - start  # C (Ciphertext position)
                plain_code = (position - key) % 26  # P = (C - K) % 26
                decrypted_char = chr(
                    plain_code + start
                )  # Convert to decrypted character
                decrypted_text += decrypted_char

                # Add step-by-step explanation in HTML
                steps_html += f"<p><b>Step {i + 1}:</b> Decrypt '{escape(char)}'</p>"
                steps_html += f"<p>&nbsp;&nbsp;P = (C - K) mod 26</p>"
                steps_html += f"<p>&nbsp;&nbsp;P = ({position} - {key}) mod 26</p>"
                steps_html += f"<p>&nbsp;&nbsp;P = {position - key} / 26</p>"
                steps_html += (
                    f"<p>&nbsp;&nbsp;P = {plain_code} -> '{escape(decrypted_char)}'</p>"
                )
            else:
                decrypted_text += char
                steps_html += (
                    f"<p><b>Step {i + 1}:</b> Non-alphabetic character, no change</p>"
                )

        return decrypted_text, steps_html


# VIGENERE CIPHER
def vigenere_encrypt(plaintext, key):
    ciphertext = []
    key = key.lower()  # make sure the key is in lowercase
    key_length = len(key)
    key_index = 0

    for char in plaintext:
        if char.isalpha():
            shift = ord(key[key_index % key_length]) - ord("a")
            if char.islower():
                encrypted_char = chr((ord(char) - ord("a") + shift) % 26 + ord("a"))
            else:
                encrypted_char = chr((ord(char) - ord("A") + shift) % 26 + ord("A"))
            ciphertext.append(encrypted_char)
            key_index += 1
        else:
            # Non-alphabetic characters are not encrypted
            ciphertext.append(char)

    return "".join(ciphertext)


def vigenere_decrypt(ciphertext, key):
    plaintext = []
    key = key.lower()
    key_length = len(key)
    key_index = 0

    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index % key_length]) - ord("a")
            if char.islower():
                decrypted_char = chr((ord(char) - ord("a") - shift) % 26 + ord("a"))
            else:
                decrypted_char = chr((ord(char) - ord("A") - shift) % 26 + ord("A"))
            plaintext.append(decrypted_char)
            key_index += 1
        else:
            plaintext.append(char)

    return "".join(plaintext)


# PLAYFAIR CIPHER
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
    return [matrix[i : i + 5] for i in range(0, 25, 5)]


def prepare_text(text):
    text = text.upper().replace("J", "I")
    clean_text = "".join([char if char.isalpha() else " " for char in text])

    digraphs = []
    i = 0
    while i < len(clean_text):
        if clean_text[i] == " ":
            digraphs.append(" ")
            i += 1
            continue

        if (
            i + 1 < len(clean_text)
            and clean_text[i + 1] != " "
            and clean_text[i] == clean_text[i + 1]
        ):
            digraphs.append(clean_text[i] + "X")
            i += 1
        elif i + 1 < len(clean_text) and clean_text[i + 1] != " ":
            digraphs.append(clean_text[i] + clean_text[i + 1])
            i += 2
        else:
            digraphs.append(clean_text[i] + "X")
            i += 1

    return digraphs


def find_position(matrix, char):
    for i, row in enumerate(matrix):
        if char in row:
            return i, row.index(char)
    raise ValueError(f"Character {char} not found in matrix")


def playfair_encrypt_decrypt(matrix, digraph, mode="encrypt"):
    if digraph == " ":
        return " "

    try:
        row1, col1 = find_position(matrix, digraph[0])
        row2, col2 = find_position(matrix, digraph[1])
    except ValueError as e:
        raise e

    if row1 == row2:
        if mode == "encrypt":
            col1 = (col1 + 1) % 5
            col2 = (col2 + 1) % 5
        else:
            col1 = (col1 - 1) % 5
            col2 = (col2 - 1) % 5
    elif col1 == col2:
        if mode == "encrypt":
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
    result = ""
    solution_steps_html = f"<h3>Playfair Cipher Solution for '{text}'</h3>"

    # Display the matrix in a column-wise format
    solution_steps_html += f"<h3><b>Matrix:</b><pre>"
    for row in matrix:
        solution_steps_html += (
            " ".join(row) + "\n"
        )  # Stack each row on top of each other
    solution_steps_html += "</pre></h3>"

    for i, digraph in enumerate(digraphs):
        if digraph == " ":
            result += " "
            continue

        solution_steps_html += (
            f"<p><b>Step {i + 1}:</b> Encrypting/Decrypting Digraph: '{digraph}'</p>"
        )

        try:
            result += playfair_encrypt_decrypt(matrix, digraph, mode)
            solution_steps_html += f"<p>&nbsp;&nbsp;Resulting Pair: '{result[-2:]}'</p>"
        except Exception as e:
            solution_steps_html += (
                f"<p>Error encrypting/decrypting digraph {digraph}: {e}</p>"
            )

    return result, solution_steps_html


# SINGLE COLUMNAR
def single_columnar_cipher(text, keyword, mode):
    steps = []  # Collect steps for display
    grids = []  # Collect grids for visualization
    decrypted_str = []

    if mode == "encrypt":
        steps.append("Starting Encryption Process... <br>")
        text = text.replace(" ", "_").upper()
        keyword = keyword.upper()
        steps.append(f"Text after replacing spaces with underscores: {text} <br>")
        steps.append(f"Keyword: {keyword} <br>")

        key_len = len(keyword)
        num_rows = (len(text) + key_len - 1) // key_len  # Ceiling division

        padding = "_" * (num_rows * key_len - len(text))
        text += padding
        steps.append(f"Padded text: {text} <br>")

        grid = [["" for _ in range(key_len)] for _ in range(num_rows)]
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
            steps.append(
                f"Reading Column {idx + 1} (Keyword: '{keyword[idx]}'): {col_data} <br>"
            )
            ciphertext += col_data

        steps.append(f"Final Ciphertext: {ciphertext}")
        steps_str = "".join(steps)
        return ciphertext, steps_str, grids, decrypted_str
    else:
        steps.append("Starting Decryption Process... <br>")
        keyword = keyword.upper()
        steps.append(f"Keyword: {keyword} <br>")

        key_len = len(keyword)
        num_rows = (len(text) + key_len - 1) // key_len

        padding = "_" * (num_rows * key_len - len(text))
        text += padding
        steps.append(f"Padded ciphertext: {text} <br>")

        grid = [["" for _ in range(key_len)] for _ in range(num_rows)]

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
        plaintext = "".join("".join(row) for row in grid).rstrip("_").replace("_", " ")
        steps.append(f"Final Decrypted Text: {plaintext} <br>")
        steps_str = "".join(steps)
        return plaintext, steps_str, grids, decrypted_str


# DOUBLE COLUMNAR
def perform_double_columnar_cipher(text, keyword, mode):
    steps = []  # Collect steps for display
    grids = []  # Collect grids for visualization
    decrypted_str = ""

    if mode == "encrypt":
        steps.append("Starting Encryption Process... <br>")
        text = text.replace(" ", "_").upper()
        keyword = keyword.upper()
        steps.append(f"Text after replacing spaces with underscores: {text} <br>")
        steps.append(f"Keyword: {keyword} <br>")

        key_len = len(keyword)
        num_rows = (len(text) + key_len - 1) // key_len  # Ceiling division

        padding = "_" * (num_rows * key_len - len(text))
        text += padding
        steps.append(f"Padded text: {text} <br>")

        grid = [["" for _ in range(key_len)] for _ in range(num_rows)]
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
            steps.append(
                f"Reading Column {idx + 1} (Keyword: '{keyword[idx]}'): {col_data} <br>"
            )
            ciphertext += col_data

        steps.append(f"Final Ciphertext: {ciphertext}")
        steps_str = "".join(steps)
        return ciphertext, steps_str, grids, decrypted_str
    else:
        steps.append("Starting Decryption Process... <br>")
        keyword = keyword.upper()
        steps.append(f"Keyword: {keyword} <br>")

        key_len = len(keyword)
        num_rows = (len(text) + key_len - 1) // key_len

        padding = "_" * (num_rows * key_len - len(text))
        text += padding
        steps.append(f"Padded ciphertext: {text} <br>")

        grid = [["" for _ in range(key_len)] for _ in range(num_rows)]

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
        steps_str = "".join(steps)
        return decrypted_str, steps_str, grids, decrypted_str


def double_columnar_cipher(text, key, key2, mode):
    steps = []  # Collect steps for display
    if mode == "encrypt":

        first_pass, steps_str, grids, decrypted_str = perform_double_columnar_cipher(
            text, key, mode
        )

        second_pass, steps_str2, grids2, decrypted_str = perform_double_columnar_cipher(
            first_pass, key2, mode
        )

        # Join the steps list into a single string for display
        print(text)
        print(first_pass)
        print(second_pass)
        return second_pass, steps_str, steps_str2, grids, grids2, decrypted_str
    else:

        first_pass, steps_str, grids, decrypted_str = perform_double_columnar_cipher(
            text, key2, mode
        )

        second_pass, steps_str2, grids2, decrypted_str = perform_double_columnar_cipher(
            first_pass, key, mode
        )

        print(text)
        print(first_pass)
        print(second_pass)
        return second_pass, steps_str, steps_str2, grids, grids2, decrypted_str


# Advanced Encryption Standard
def encrypt_data(plaintext, key, key_size, iv, mode):
    context = {"process_log": []}

    try:
        if mode == "encrypt":
            encrypted_data, log = aes_encrypt(plaintext, key, key_size, iv)
            if encrypted_data:
                context["data"] = encrypted_data
            context["process_log"] = log
        elif mode == "decrypt":
            decrypted_data, log = aes_decrypt(plaintext, key, key_size, iv)
            if decrypted_data:
                context["data"] = decrypted_data
            context["process_log"] = log
        else:
            raise ValueError("Invalid mode. Choose 'encrypt' or 'decrypt'.")
    except Exception as e:
        context["process_log"].append(f"Error: {str(e)}")

    return context


# Validate or Generate IV
def validate_or_generate_iv(iv, for_encryption=False):
    if not iv and for_encryption:
        return os.urandom(16)
    try:
        iv_bytes = b64decode(iv)
        if len(iv_bytes) != 16:
            raise ValueError("IV must be 16 bytes long after decoding.")
        return iv_bytes
    except Exception as e:
        raise ValueError(f"Invalid IV: {str(e)}")


def validate_base64(input_string):
    try:
        # Ensure padding for Base64
        padded_input = input_string + "=" * (-len(input_string) % 4)
        base64.b64decode(padded_input)
        return padded_input
    except Exception as e:
        print(f"Invalid Base64 string: {str(e)}")
        return None


# Encryption Function
def aes_encrypt(plaintext, key, key_size, iv):
    log = []
    try:
        # Validate key size
        if key_size not in [128, 192, 256]:
            raise ValueError("Invalid key size. Choose 128, 192, or 256 bits.")

        # Prepare key
        key_bytes = key.encode("utf-8")
        key_bytes = key_bytes[: key_size // 8].ljust(key_size // 8, b"\0")
        log.append(f"Key adjusted to {key_size} bits: {key_bytes}")

        # Generate IV if not provided
        iv_bytes = validate_or_generate_iv(iv, for_encryption=True)
        log.append(f"IV (16 bytes): {iv_bytes}")

        # Prepare plaintext
        plaintext_bytes = plaintext.encode("utf-8")
        log.append(f"Plaintext bytes: {plaintext_bytes}")

        # Apply padding
        padded_data = pad(plaintext_bytes, AES.block_size)
        log.append(f"Padded plaintext: {padded_data}")

        # Initialize AES cipher
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv_bytes)

        # Encrypt and encode
        ciphertext = cipher.encrypt(padded_data)
        combined = iv_bytes + ciphertext
        encrypted_data = b64encode(combined).decode("utf-8")
        log.append(f"Encrypted Base64 ciphertext (IV + Ciphertext): {encrypted_data}")

        return encrypted_data, log
    except Exception as e:
        log.append(f"Error during encryption: {str(e)}")
        return None, log


# Decryption Function
def aes_decrypt(ciphertext, key, key_size, iv):
    log = []
    try:
        # Validate key size
        if key_size not in [128, 192, 256]:
            raise ValueError("Invalid key size. Choose 128, 192, or 256 bits.")

        # Prepare key
        key_bytes = key.encode("utf-8")
        key_bytes = key_bytes[: key_size // 8].ljust(key_size // 8, b"\0")
        log.append(f"Key adjusted to {key_size} bits: {key_bytes}")

        # Decode Base64 ciphertext
        padded_ciphertext = ciphertext + "=" * (-len(ciphertext) % 4)
        combined = b64decode(padded_ciphertext)
        log.append(f"Base64-decoded combined data (length {len(combined)}): {combined}")

        if len(combined) < 16:
            raise ValueError("Combined data too short to contain an IV and ciphertext.")

        iv_bytes = combined[:16]  # Extract IV
        ciphertext_bytes = combined[16:]  # Extract Ciphertext
        log.append(f"Extracted IV (16 bytes): {iv_bytes}")
        log.append(f"Ciphertext bytes: {ciphertext_bytes}")

        # Initialize AES cipher
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv_bytes)

        # Decrypt and remove padding
        decrypted_padded = cipher.decrypt(ciphertext_bytes)
        log.append(f"Decrypted padded plaintext: {decrypted_padded}")

        plaintext = unpad(decrypted_padded, AES.block_size).decode("utf-8")
        log.append(f"Decrypted plaintext: {plaintext}")

        return plaintext, log
    except Exception as e:
        log.append(f"Error during decryption: {str(e)}")
        return None, log
