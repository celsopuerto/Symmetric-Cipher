from django.shortcuts import render, redirect
from django.http import HttpResponse
from .utils import perform_caesar_cipher_encryption, perform_caesar_cipher_decryption

# Create your views here.
def landing(request):
    return render(request, 'landing.html')

def cipher(request):
    return render(request, 'page.html')

def caesar_cipher_encrypt(request):
    key = int(request.GET.get('key', 0))  # Default to 0 if no key is provided
    text = request.GET.get('text', '')
    encrypted_text = perform_caesar_cipher_encryption(text, key)
    return render(request, 'page.html', {'encrypted_text': encrypted_text, 'key': key, 'text': text})

def caesar_cipher_decrypt(request):
    key = int(request.GET.get('key', 0))  # Default to 0 if no key is provided
    text = request.GET.get('text', '')
    encrypted_text = perform_caesar_cipher_decryption(text, key)
    return render(request, 'page.html', {'encrypted_text': encrypted_text, 'key': key, 'text': text})