function resetFields() {
    // Reset input fields
    document.getElementById('key-input').value = '';
    document.getElementById('key-input-2').value = '';
    document.getElementById('text-input').value = '';
    document.getElementById('result-output').textContent = '';

    // Clear the solution modal steps container
    document.getElementById('modal-steps-container').innerHTML = '';

    // Ensure the modal is closed
    document.getElementById('solution-modal').style.display = 'none';
}