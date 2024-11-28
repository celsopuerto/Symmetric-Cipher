def single_columnar_encrypt(plaintext, keyword):
    print("\n--- Encryption ---")
    # Replace spaces with underscores and convert to uppercase
    plaintext = plaintext.replace(" ", "_").upper()
    keyword = keyword.upper()
    
    # Calculate dimensions of the grid
    key_len = len(keyword)
    num_rows = (len(plaintext) + key_len - 1) // key_len  # Ceiling division
    
    # Pad plaintext with '_'
    padding = '_' * (num_rows * key_len - len(plaintext))
    plaintext += padding
    
    # Create the grid row-wise
    grid = [['' for _ in range(key_len)] for _ in range(num_rows)]
    k = 0
    for i in range(num_rows):
        for j in range(key_len):
            grid[i][j] = plaintext[k]
            k += 1
    
    # Display the grid
    print("\nGrid:")
    for row in grid:
        print(" ".join(row))
    
    # Sort the keyword and create a mapping of column indices
    sorted_keyword = sorted((char, idx) for idx, char in enumerate(keyword))
    column_order = [idx for char, idx in sorted_keyword]
    
    # Generate ciphertext column-wise
    ciphertext = ""
    print("\nColumn order (sorted by keyword):")
    for idx in column_order:
        print(f"Column {idx + 1} (Letter: '{keyword[idx]}')")
        for row in grid:
            ciphertext += row[idx]
    
    print("\nCiphertext:", ciphertext)
    return ciphertext

# Input and call the function
plaintext = input("Enter plaintext: ")
keyword = input("Enter keyword: ")

ciphertext = single_columnar_encrypt(plaintext, keyword)

def single_columnar_decrypt(ciphertext, keyword):
    print("\n--- Decryption ---")
    keyword = keyword.upper()
    
    # Calculate dimensions of the grid
    key_len = len(keyword)
    num_rows = (len(ciphertext) + key_len - 1) // key_len
    
    # Create an empty grid
    grid = [['' for _ in range(key_len)] for _ in range(num_rows)]
    
    # Sort the keyword and create a mapping of column indices
    sorted_keyword = sorted((char, idx) for idx, char in enumerate(keyword))
    column_order = [idx for char, idx in sorted_keyword]
    
    # Fill the grid column-wise based on sorted keyword
    k = 0
    print("\nFilling grid column-wise based on sorted keyword:")
    for idx in column_order:
        print(f"Column {idx + 1} (Letter: '{keyword[idx]}')")
        for i in range(num_rows):
            grid[i][idx] = ciphertext[k]
            k += 1
    
    # Display the filled grid
    print("\nFilled Grid:")
    for row in grid:
        print(" ".join(row))
    
    # Read the plaintext row-wise
    plaintext = ""
    for row in grid:
        plaintext += "".join(row)
    
    # Remove trailing underscores and restore underscores to spaces
    plaintext = plaintext.rstrip('_').replace("_", " ")
    print("\nDecrypted Plaintext:", plaintext)
    return plaintext
ciphertext_to_decrypt = input("\nEnter ciphertext: ")
keyword_for_decryption = input("Enter keyword: ")
decrypted_text = single_columnar_decrypt(ciphertext_to_decrypt, keyword_for_decryption)