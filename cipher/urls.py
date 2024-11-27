from django.urls import path
from cipher import views

urlpatterns = [
    path('cipher', views.cipher, name="cipher"),
]