def vigenere_encrypt(plaintext, key):
    ciphertext = []
    key = key.lower()  # make sure the key is in lowercase
    key_length = len(key)
    key_index = 0
    
    for char in plaintext:
        if char.isalpha():
            shift = ord(key[key_index % key_length]) - ord('a')
            if char.islower():
                encrypted_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            else:
                encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            ciphertext.append(encrypted_char)
            key_index += 1
        else:
            # Non-alphabetic characters are not encrypted
            ciphertext.append(char)
    
    return ''.join(ciphertext)


def vigenere_decrypt(ciphertext, key):
    plaintext = []
    key = key.lower()
    key_length = len(key)
    key_index = 0
    
    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index % key_length]) - ord('a')
            if char.islower():
                decrypted_char = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            else:
                decrypted_char = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            plaintext.append(decrypted_char)
            key_index += 1
        else:
            plaintext.append(char)
    
    return ''.join(plaintext)




# views.py
from django.http import JsonResponse
from .cipher import vigenere_encrypt, vigenere_decrypt

def encrypt_view(request):
    text = request.GET.get('text', '')
    key = request.GET.get('key', '')
    
    if text and key:
        encrypted_text = vigenere_encrypt(text, key)
        return JsonResponse({'encrypted_text': encrypted_text})
    else:
        return JsonResponse({'error': 'Text and key parameters are required.'}, status=400)

def decrypt_view(request):
    text = request.GET.get('text', '')
    key = request.GET.get('key', '')
    
    if text and key:
        decrypted_text = vigenere_decrypt(text, key)
        return JsonResponse({'decrypted_text': decrypted_text})
    else:
        return JsonResponse({'error': 'Text and key parameters are required.'}, status=400)
