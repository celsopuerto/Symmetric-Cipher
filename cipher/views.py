from django.shortcuts import render, redirect
from django.http import HttpResponse
from .utils import perform_caesarcipher_encryp_decrypt, perform_playfair_cipher

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


# PLAYFAIR CIPHER
def playfair_cipher(request):
    key = request.GET.get('key', 0)
    text = request.GET.get('text', '')
    mode = request.GET.get('mode', '')
    cipher = 'playfair'
    encrypted_text, steps = perform_playfair_cipher(key, text, mode)
    return render(request, 'page.html', {'data': encrypted_text, 'key': key, 'text': text, 'steps': steps, 'mode': mode, 'cipher': cipher})