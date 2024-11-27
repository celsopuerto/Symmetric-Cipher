# Symmetric Cipher Tool 🔐  

A Django-powered web application that provides a suite of symmetric encryption and decryption tools. Supports classical ciphers like Caesar, Vigenère, Playfair, Single Columnar, and Double Columnar, as well as the modern AES cipher.

## Features  
- User-friendly interface for encryption and decryption.  
- Support for both classical and modern symmetric ciphers.  
- Light/Dark mode toggle for better accessibility.  

## Getting Started  

Follow these steps to set up the Symmetric Cipher Tool on your local machine.  

### Prerequisites  
Ensure you have the following installed on your system:  
- Python 3.8 or higher  
- pip (Python package installer)  
- Git  

### Installation  

1. Clone the repository:  
   ```bash
   git clone https://github.com/celsopuerto/Symmetric-Cipher.git
   cd symmetric-cipher-tool

2. Create a virtual environment:
   ```bash
   python -m venv venv
   
3. Activate the virtual environment:
  On Windows:
    ```bash
    venv\Scripts\activate

  On macOS/Linux:
    ```bash 
    
    source venv/bin/activate

4. Install dependencies:
    ```bash
    pip install -r requirements.txt
    
5. Apply database migrations:
   ```bash
    python manage.py migrate
   
6. Run the development server:
    ```bash
   python manage.py runserver
    
7. Open your browser and navigate to:
    ```bash
    http://127.0.0.1:8000/


<h1>Usage</h1>
Select a cipher from the user interface.
Enter the text and keys as required.
Choose to Encrypt or Decrypt.
View the result instantly.
Contributing
Contributions are welcome! If you'd like to improve this project, please:

<h2>Acknowledgments</h2>
This project is inspired by the rich history of symmetric ciphers and aims to provide a user-friendly tool for exploring these encryption techniques.
