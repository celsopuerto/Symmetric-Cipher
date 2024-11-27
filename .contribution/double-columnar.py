import math

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


def double_columnar_cipher(text, key1, key2, mode='encrypt'):
    if mode == 'encrypt':
        intermediate = columnar_transposition_encrypt(text, key1)
        return columnar_transposition_encrypt(intermediate, key2)
    elif mode == 'decrypt':
        intermediate = columnar_transposition_decrypt(text, key2)
        return columnar_transposition_decrypt(intermediate, key1)


# Example Usage
if __name__ == "__main__":
    plaintext = "thisisatestmessage"
    key1 = "KEY1"
    key2 = "LOCK2"

    # Encrypt
    encrypted_text = double_columnar_cipher(plaintext, key1, key2, mode='encrypt')
    print(f"Encrypted Text: {encrypted_text}")

    # Decrypt
    decrypted_text = double_columnar_cipher(encrypted_text, key1, key2, mode='decrypt')
    print(f"Decrypted Text: {decrypted_text}")