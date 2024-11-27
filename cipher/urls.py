from django.urls import path
from . import views

app_name = 'cipher'

urlpatterns = [
    path('cipher', views.cipher, name="cipher"),
    
    #CAESAR CIPHER
    path('caesar_cipher_encrypt/', views.caesar_cipher_encrypt, name="caesar_cipher_encrypt"),
    path('caesar_cipher_decrypt/', views.caesar_cipher_decrypt, name="caesar_cipher_decrypt"),
]