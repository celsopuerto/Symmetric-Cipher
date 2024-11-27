from django.shortcuts import render, redirect
from django.http import HttpResponse
from .utils import perform_caesarcipher_encryp_decrypt, perform_playfair_cipher, double_columnar_cipher

# Create your views here.
def landing(request):
    return render(request, 'landing.html')

def cipher_view(request):
    return render(request, 'page.html')


# CAECAR CIPHER
def caesar_cipher(request):
    key = int(request.GET.get('key', 0))  # Default to 0 if no key is provided
    text = request.GET.get('text', '')
    mode = request.GET.get('mode', '')
    encrypted_text, steps = perform_caesarcipher_encryp_decrypt(text, key, mode)
    cipher = 'caesar'
    return render(request, 'page.html', {'data': encrypted_text, 'key': key, 'text': text, 'steps': steps, 'mode': mode, 'cipher': cipher})


# VIGENERE CIPHER
def vigenere_cipher(request):
    return render(request, 'page.html')


# PLAYFAIR CIPHER
def playfair_cipher(request):
    key = request.GET.get('key', 0)
    text = request.GET.get('text', '')
    mode = request.GET.get('mode', '')
    cipher = 'playfair'
    encrypted_text, steps = perform_playfair_cipher(key, text, mode)
    return render(request, 'page.html', {'data': encrypted_text, 'key': key, 'text': text, 'steps': steps, 'mode': mode, 'cipher': cipher})


# SINGLE COLUMNAR CIPHER
def singlecolumnar_cipher(request):
    return render(request, 'page.html')


# DOUBLE COLUMNAR CIPHER
def doublecolumnar_cipher(request):
    text = request.GET.get('text', '')
    key = request.GET.get('key', '')
    key2 = request.GET.get('key2', '')
    mode = request.GET.get('mode', '')
    cipher = 'double-columnar'
    steps = ""
    encrypted_text = double_columnar_cipher(text, key, key2, mode)
    return render(request, 'page.html', {'data': encrypted_text, 'key': key, 'key2': key2, 'text': text, 'steps': steps, 'mode': mode, 'cipher': cipher})


# ADVANCE ENCRYPTION STANDARD
def aes_cipher(request):
    return render(request, 'page.html')