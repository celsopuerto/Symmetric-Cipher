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

function copyToClipboard() {
    const resultText = document.getElementById('result-output').textContent.trim();
    
    // Check if there's text to copy
    if (resultText) {
        const textArea = document.createElement('textarea');
        textArea.value = resultText;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);

        // Show the success notification
        const successNotification = document.getElementById('copy-notification');
        successNotification.classList.add('show');
        setTimeout(() => {
            successNotification.classList.remove('show');
        }, 3000); // Duration of notification

    } else {
        // Show the error notification (nothing to copy)
        const errorNotification = document.getElementById('error-notification');
        errorNotification.classList.add('show');
        setTimeout(() => {
            errorNotification.classList.remove('show');
        }, 3000); // Duration of notification
    }
}

document.addEventListener("DOMContentLoaded", function () {
    // Select all messages in the message container
    const messages = document.querySelectorAll('.message');
    
    // Loop through each message
    messages.forEach(message => {
        // Set a timeout to remove the message after 4 seconds
        setTimeout(() => {
            // Apply the hideMessage animation
            message.style.animation = "hideMessage 0.5s ease-out forwards";
            
            // After the animation duration, remove the message from the DOM
            setTimeout(() => {
                message.remove();
            }, 500); // Matches the duration of the hideMessage animation
        }, 3000); // Show message for 4 seconds before disappearing
    });
});