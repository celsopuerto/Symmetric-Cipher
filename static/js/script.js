function resetFields() {
    // Reset input fields
    document.getElementById('key-input').value = '';
    document.getElementById('key-input-2').value = '';
    document.getElementById('text-input').value = '';
    document.getElementById('result-output').textContent = '';
    // Reset the active cipher selection
    currentCipher = 'caesar';
    selectCipher('caesar');  // Resets to Caesar cipher (default)
}