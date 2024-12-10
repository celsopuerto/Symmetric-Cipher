from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from cryptography.exceptions import InvalidKey, InvalidSignature
from .utils import (
    perform_caesarcipher_encryp_decrypt,
    perform_playfair_cipher,
    single_columnar_cipher,
    double_columnar_cipher,
    vigenere_encrypt,
    vigenere_decrypt,
    encrypt_data,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os


# Create your views here.
def landing(request):
    return render(request, "landing.html")


def cipher_view(request):
    return render(request, "page.html")


# CAECAR CIPHER
def caesar_cipher(request):
    # Get the key from the request; default to 0 if not provided
    key = request.GET.get("key", "").strip()  # Strip any unwanted spaces

    # Validate if key, text, and mode are provided
    text = request.GET.get("text", "").strip()
    mode = request.GET.get("mode", "").strip()

    if not key or not text or not mode:
        messages.error(request, "Please fill all inputs")
        return render(request, "page.html")

    # Attempt to convert key to an integer
    try:
        key = int(key)  # Convert key to integer
    except ValueError:
        messages.error(request, "Invalid key. Please provide a valid integer key.")
        return render(request, "page.html")
    encrypted_text, steps = perform_caesarcipher_encryp_decrypt(text, key, mode)

    encrypted_text = encrypted_text.upper()
    cipher = "caesar"
    return render(
        request,
        "page.html",
        {
            "data": encrypted_text,
            "key": key,
            "text": text,
            "steps": steps,
            "mode": mode,
            "cipher": cipher,
        },
    )


# VIGENERE CIPHER
def vigenere_cipher(request):
    key = request.GET.get("key", "")
    text = request.GET.get("text", "")
    mode = request.GET.get("mode", "")

    if not key or not text or not mode:
        messages.error(request, "Please fill all inputs")
        return render(request, "page.html")
    if mode == "encrypt":
        data = vigenere_encrypt(text, key)
    else:
        data = vigenere_decrypt(text, key)

    data = data.upper()
    cipher = "vigenere"
    return render(
        request,
        "page.html",
        {"data": data, "key": key, "text": text, "cipher": cipher, "mode": mode},
    )


# PLAYFAIR CIPHER
def playfair_cipher(request):
    key = request.GET.get("key", 0)
    text = request.GET.get("text", "")
    mode = request.GET.get("mode", "")
    if not key or not text or not mode:
        messages.error(request, "Please fill all inputs")
        return render(request, "page.html")
    cipher = "playfair"
    encrypted_text, steps = perform_playfair_cipher(key, text, mode)

    encrypted_text = encrypted_text.upper()
    return render(
        request,
        "page.html",
        {
            "data": encrypted_text,
            "key": key,
            "text": text,
            "steps": steps,
            "mode": mode,
            "cipher": cipher,
        },
    )


# SINGLE COLUMNAR CIPHER
def singlecolumnar_cipher(request):
    key = request.GET.get("key", 0)
    text = request.GET.get("text", "")
    mode = request.GET.get("mode", "")
    if not key or not text or not mode:
        messages.error(request, "Please fill all inputs")
        return render(request, "page.html")
    cipher = "single-columnar"
    steps = []
    grids = []
    encrypted_text, steps, grids, decrypted_str = single_columnar_cipher(
        text, key, mode
    )

    decrypted_str = decrypted_str
    encrypted_text = encrypted_text
    return render(
        request,
        "page.html",
        {
            "data": encrypted_text,
            "data2": decrypted_str,
            "key": key,
            "text": text,
            "steps": steps,
            "grids": grids,
            "mode": mode,
            "cipher": cipher,
        },
    )


# DOUBLE COLUMNAR CIPHER
def doublecolumnar_cipher(request):
    text = request.GET.get("text", "")
    key = request.GET.get("key", "")
    key2 = request.GET.get("key2", "")
    mode = request.GET.get("mode", "")
    if not key or not key2 or not text or not mode:
        messages.error(request, "Please fill all inputs")
        return render(request, "page.html")
    cipher = "double-columnar"
    encrypted_text, steps, steps2, grids, grids2, decrypted_str = (
        double_columnar_cipher(text, key, key2, mode)
    )
    print(f"{steps2} {grids2}")

    encrypted_text = encrypted_text.upper()
    decrypted_str = decrypted_str.upper()
    return render(
        request,
        "page.html",
        {
            "data": encrypted_text,
            "data2": decrypted_str,
            "key": key,
            "key2": key2,
            "text": text,
            "steps": steps,
            "steps2": steps2,
            "grids": grids,
            "grids2": grids2,
            "mode": mode,
            "cipher": cipher,
        },
    )


# ADVANCE ENCRYPTION STANDARD
def aes_cipher_view(request):
    # Get query parameters
    plaintext = request.GET.get("text", "")
    key = request.GET.get("key", "")
    key_size = request.GET.get("key_size", "")
    iv = request.GET.get("iv", "")
    mode = request.GET.get("mode", "").lower()  # Case-insensitive

    if not key or not plaintext or not mode or not key_size:
        messages.error(request, "Please fill all inputs")
        return render(request, "page.html")

    try:
        key_size = int(key_size)
        cipher = "aes"
        context = encrypt_data(plaintext, key, key_size, iv, mode)
        data = context.get("data", "")
        steps = format_logs_to_html(context["process_log"])
    except Exception as e:
        data = ""
        steps = [f"Error: {str(e)}"]
    return render(
        request,
        "page.html",
        {
            "cipher": cipher,
            "mode": mode,
            "text": plaintext,
            "key": key,
            "key2": iv,
            "key_size": key_size,
            "data": data,
            "steps": steps,
        },
    )


def format_logs_to_html(log):
    html_output = ""
    for i, entry in enumerate(log, start=1):
        html_output += f"<p>{i}. {entry}</p>\n"
    return html_output
