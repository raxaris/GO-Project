function updateLoadingBar(progress) {
    const loadingBar = document.getElementById("loadingBar");
    loadingBar.style.width = progress + "%";
}

function simulateLoading() {
    const totalSteps = 100;
    let currentStep = 0;

    function update() {
        if (currentStep <= totalSteps) {
            updateLoadingBar((currentStep / totalSteps) * 100);
            currentStep++;
            setTimeout(update, 25);
        }
    }

    update();
}

simulateLoading();