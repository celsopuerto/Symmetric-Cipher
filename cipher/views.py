from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from cryptography.exceptions import InvalidKey, InvalidSignature
from .utils import perform_caesarcipher_encryp_decrypt, perform_playfair_cipher, single_columnar_cipher, double_columnar_cipher, PerformAESCipher, vigenere_encrypt, vigenere_decrypt

# Create your views here.
def landing(request):
    return render(request, 'landing.html')

def cipher_view(request):
    return render(request, 'page.html')


# CAECAR CIPHER
def caesar_cipher(request):
    # Get the key from the request; default to 0 if not provided
    key = request.GET.get('key', '').strip()  # Strip any unwanted spaces

    # Validate if key, text, and mode are provided
    text = request.GET.get('text', '').strip()
    mode = request.GET.get('mode', '').strip()

    if not key or not text or not mode:
        messages.error(request, 'Please fill all inputs')
        return render(request, 'page.html')

    # Attempt to convert key to an integer
    try:
        key = int(key)  # Convert key to integer
    except ValueError:
        messages.error(request, 'Invalid key. Please provide a valid integer key.')
        return render(request, 'page.html')
    encrypted_text, steps = perform_caesarcipher_encryp_decrypt(text, key, mode)
    
    encrypted_text = encrypted_text.upper()
    cipher = 'caesar'
    return render(request, 'page.html', {'data': encrypted_text, 'key': key, 'text': text, 'steps': steps, 'mode': mode, 'cipher': cipher})


# VIGENERE CIPHER
def vigenere_cipher(request):
    key = request.GET.get('key', '')
    text = request.GET.get('text', '')
    mode = request.GET.get('mode', '')

    if not key or not text or not mode:
        messages.error(request, 'Please fill all inputs')
        return render(request, 'page.html')
    if mode == 'encrypt':
        data = vigenere_encrypt(text, key)
    else:
        data = vigenere_decrypt(text, key)
        
    data = data.upper()
    cipher = 'vigenere'
    return render(request, 'page.html', {'data': data, 'key': key, 'text': text, 'cipher': cipher, 'mode': mode})


# PLAYFAIR CIPHER
def playfair_cipher(request):
    key = request.GET.get('key', 0)
    text = request.GET.get('text', '')
    mode = request.GET.get('mode', '')
    if not key or not text or not mode:
        messages.error(request, 'Please fill all inputs')
        return render(request, 'page.html')
    cipher = 'playfair'
    encrypted_text, steps = perform_playfair_cipher(key, text, mode)
    
    encrypted_text = encrypted_text.upper()
    return render(request, 'page.html', {'data': encrypted_text, 'key': key, 'text': text, 'steps': steps, 'mode': mode, 'cipher': cipher})


# SINGLE COLUMNAR CIPHER
def singlecolumnar_cipher(request):
    key = request.GET.get('key', 0)
    text = request.GET.get('text', '')
    mode = request.GET.get('mode', '')
    if not key or not text or not mode:
        messages.error(request, 'Please fill all inputs')
        return render(request, 'page.html')
    cipher = 'single-columnar'
    steps = []
    grids = []
    encrypted_text, steps, grids, decrypted_str = single_columnar_cipher(text, key, mode)
    
    decrypted_str = decrypted_str.upper()
    encrypted_text = encrypted_text.upper()
    return render(request, 'page.html', {'data': encrypted_text, 'data2': decrypted_str, 'key': key, 'text': text, 'steps': steps, 'grids': grids, 'mode': mode, 'cipher': cipher})


# DOUBLE COLUMNAR CIPHER
def doublecolumnar_cipher(request):
    text = request.GET.get('text', '')
    key = request.GET.get('key', '')
    key2 = request.GET.get('key2', '')
    mode = request.GET.get('mode', '')
    if not key or not key2 or not text or not mode:
        messages.error(request, 'Please fill all inputs')
        return render(request, 'page.html')
    cipher = 'double-columnar'
    encrypted_text, steps, steps2, grids, grids2, decrypted_str = double_columnar_cipher(text, key, key2, mode)
    print(f'{steps2} {grids2}')
    
    encrypted_text = encrypted_text.upper()
    decrypted_str = decrypted_str.upper()
    return render(request, 'page.html', {'data': encrypted_text, 'data2': decrypted_str, 'key': key, 'key2': key2, 'text': text, 'steps': steps, 'steps2': steps2, 'grids': grids, 'grids2': grids2, 'mode': mode, 'cipher': cipher})


# ADVANCE ENCRYPTION STANDARD
# Secret key for AES (should be stored securely in environment variables)
SECRET_KEY = b'myverysecretkey12'  # 16 bytes (128 bits)

# Initialize the AES Cipher
aes_cipher = PerformAESCipher(SECRET_KEY)

def aes_cipher_view(request):
    # Get query parameters
    text = request.GET.get('text', '')
    data = request.GET.get('key', '')
    mode = request.GET.get('mode', '').lower()  # Case-insensitive
    if not data or not text or not mode:
        messages.error(request, 'Please fill all inputs')
        return render(request, 'page.html')
    cipher = 'aes'
    steps = ""  # Placeholder for any additional debugging or step information

    # Validate required inputs
    if not mode or mode not in ['encrypt', 'decrypt']:
        return JsonResponse({'error': 'Invalid mode. Use "encrypt" or "decrypt".'}, status=400)
    if not data:
        return JsonResponse({'error': 'No key provided for encryption/decryption.'}, status=400)

    try:
        if mode == 'encrypt':
            # Encrypt the provided data
            encrypted_data = aes_cipher.encrypt(data)
            response_data = {
                'data': encrypted_data,
                'text': text,
                'key': data,
                'mode': mode,
                'cipher': cipher,
                'steps': steps
            }
        else:  # mode == 'decrypt'
            # Decrypt the provided data
            decrypted_data = aes_cipher.decrypt(data)
            response_data = {
                'data': decrypted_data,
                'text': text,
                'key': data,
                'mode': mode,
                'cipher': cipher,
                'steps': steps
            }
        
        # Render the response in a template
        return render(request, 'page.html', response_data)
    
    except (ValueError, InvalidKey, InvalidSignature) as e:
        # Handle errors in encryption/decryption
        return JsonResponse({'error': f'Error processing data: {str(e)}'}, status=500)