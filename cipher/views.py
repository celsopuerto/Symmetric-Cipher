from django.shortcuts import render, redirect

# Create your views here.
def cipher(request):
    return render(request, 'page.html')