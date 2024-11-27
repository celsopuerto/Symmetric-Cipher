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
    solution_steps_html += f"<p><b>Matrix:</b></p><pre>"
    for row in matrix:
        solution_steps_html += " ".join(row) + "\n"  # Stack each row on top of each other
    solution_steps_html += "</pre>"

    for i, digraph in enumerate(digraphs):
        solution_steps_html += f"<p><b>Step {i + 1}:</b> Encrypting/Decrypting Digraph: '{escape(digraph)}'</p>"

        try:
            result += playfair_encrypt_decrypt(matrix, digraph, mode)
            solution_steps_html += f"<p>&nbsp;&nbsp;Resulting Pair: '{escape(result[-2:])}'</p>"
        except Exception as e:
            solution_steps_html += f"<p>Error encrypting/decrypting digraph {escape(digraph)}: {e}</p>"

    return result, solution_steps_html


#SINGLE COLUMNAR



#DOUBLE COLUMNAR
def columnar_transposition_encrypt(plaintext, key):
    # Sort key to determine column order
    key_order = sorted(list(key))
    col_order = [key.index(char) for char in key_order]

    # Fill grid with text
    columns = [''] * len(key)
    for i, char in enumerate(plaintext):
        columns[i % len(key)] += char

    # Rearrange columns based on the sorted key
    ciphertext = ''.join(columns[i] for i in col_order)
    return ciphertext


def columnar_transposition_decrypt(ciphertext, key):
    # Calculate grid dimensions
    cols = len(key)
    rows = math.ceil(len(ciphertext) / cols)
    key_order = sorted(list(key))

    # Determine column lengths
    col_lengths = [rows] * cols
    for i in range((rows * cols) - len(ciphertext)):
        col_lengths[key_order.index(key[i])] -= 1

    # Split ciphertext into columns based on lengths
    start = 0
    columns = {}
    for i, col_len in enumerate(col_lengths):
        columns[key_order[i]] = list(ciphertext[start:start + col_len])
        start += col_len

    # Reconstruct plaintext row-wise
    plaintext = ''
    for i in range(rows):
        for k in key:
            if columns[k]:
                plaintext += columns[k].pop(0)

    return plaintext


def double_columnar_cipher(text, key1, key2, mode):
    if mode == 'encrypt':
        intermediate = columnar_transposition_encrypt(text, key1)
        return columnar_transposition_encrypt(intermediate, key2)
    elif mode == 'decrypt':
        intermediate = columnar_transposition_decrypt(text, key2)
        return columnar_transposition_decrypt(intermediate, key1)