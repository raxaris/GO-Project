function showCustomAlert(message) {
    const customAlert = document.getElementById("customAlert");
    const alertMessage = document.getElementById("alertMessage");
    const overlay = document.getElementById("overlay");

    alertMessage.innerText = message;
    customAlert.style.display = "block";
    overlay.style.display = "block";
}

function closeCustomAlert() {
    const customAlert = document.getElementById("customAlert");
    const overlay = document.getElementById("overlay");
    
    customAlert.style.display = "none";
    overlay.style.display = "none";
}   