# CAESAR CIPHER
from django.utils.html import escape

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

    # If the length is odd, add 'X' to the end
    if len(text) % 2 != 0:
        text += "X"  # Add an 'X' to make the length even

    # Prepare digraphs
    digraphs = []
    i = 0
    while i < len(text):
        if i + 1 < len(text) and text[i] == text[i + 1]:
            # Insert 'X' between duplicate letters (e.g., "LL" becomes "LX")
            digraphs.append(text[i] + 'X')
            i += 1  # Only increment once to avoid skipping the next character
        else:
            digraphs.append(text[i:i + 2])  # Add the digraph
            i += 2  # Increment by 2 as we're processing a pair

    return digraphs

def find_position(matrix, char):
    # Check the position of a character in the 5x5 matrix
    for i, row in enumerate(matrix):
        if char in row:
            return i, row.index(char)
    raise ValueError(f"Character {char} not found in matrix")

def playfair_encrypt_decrypt(matrix, digraph, mode='encrypt'):
    try:
        row1, col1 = find_position(matrix, digraph[0])
        row2, col2 = find_position(matrix, digraph[1])
    except ValueError as e:
        print(f"Error in finding position of characters {digraph}: {e}")
        raise e

    if row1 == row2:
        # Same row: shift columns
        if mode == 'encrypt':
            col1 = (col1 + 1) % 5
            col2 = (col2 + 1) % 5
        else:
            col1 = (col1 - 1) % 5
            col2 = (col2 - 1) % 5
    elif col1 == col2:
        # Same column: shift rows
        if mode == 'encrypt':
            row1 = (row1 + 1) % 5
            row2 = (row2 + 1) % 5
        else:
            row1 = (row1 - 1) % 5
            row2 = (row2 - 1) % 5
    else:
        # Rectangle: swap columns
        col1, col2 = col2, col1

    return matrix[row1][col1] + matrix[row2][col2]

def perform_playfair_cipher(key, text, mode):
    # Generate the matrix from the key
    matrix = generate_matrix(key)
    print(f"Matrix: {matrix}")  # Debug: Check the matrix

    # Prepare the text and split it into digraphs
    digraphs = prepare_text(text)
    print(f"Prepared Digraphs: {digraphs}")  # Debug: Check the digraphs
    
    result = ''
    for digraph in digraphs:
        try:
            result += playfair_encrypt_decrypt(matrix, digraph, mode)
        except Exception as e:
            print(f"Error encrypting/decrypting digraph {digraph}: {e}")
            raise e

    return result