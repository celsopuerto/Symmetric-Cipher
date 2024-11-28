from django.urls import path
from . import views

app_name = 'cipher'

urlpatterns = [
    path('', views.landing, name="landing"),
    path('cipher', views.cipher_view, name="cipher"),
    
    #CAESAR CIPHER
    path('caesar_cipher', views.caesar_cipher, name="caesar_cipher"),
    
    #VIGENERE CIPHER
    path('vigenere_cipher', views.vigenere_cipher, name='vigenere_cipher'),
    
    #PLAYFAIR CIPHER
    path('playfair_cipher', views.playfair_cipher, name='playfair_cipher'),
    
    #SINGLE COLUMNAR
    path('single-columnar_cipher', views.singlecolumnar_cipher, name='single-columnar_cipher'),
    
    #DOUBLE COLUMNAR
    path('double-columnar_cipher', views.doublecolumnar_cipher, name='double-columnar_cipher'),
    
    #ADVANCED ENCRYPTION STANDARD
    path('aes_cipher', views.aes_cipher_view, name='aes_cipher'),
]