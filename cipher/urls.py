from django.urls import path
from . import views

app_name = 'cipher'

urlpatterns = [
    path('', views.landing, name="landing"),
    path('cipher', views.cipher_view, name="cipher"),
    
    #CAESAR CIPHER
    path('caesar_cipher', views.caesar_cipher, name="caesar_cipher"),
    
    #PLAYFAIR CIPHER
    path('playfair_cipher', views.playfair_cipher, name='playfair_cipher'),
]