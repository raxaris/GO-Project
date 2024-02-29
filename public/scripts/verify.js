document.addEventListener('DOMContentLoaded', function () {
    const formElement = document.getElementById('formVerify');
    console.log(formElement);

    const urlParams = new URLSearchParams(window.location.search);
    const emailInput = document.getElementById('email');
    const email = urlParams.get('email');

    if (email) {
        emailInput.value = email;
    }

    formElement.addEventListener('submit', async (event) => {
        event.preventDefault();

        console.log(email)
        let body = {
            email: email,
            verify: formElement.elements.verify.value
        };
        
        console.log(body)

        fetch("/login/verify", {
            method: "POST",
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(body)
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 200) {
                window.location.href = "/login";
            } else {
                alertMSG(data.message, "danger");
            }
        })
        .catch(error => {
            console.error("An error occurred while processing your request:", error);
            alertMSG("An error occurred while processing your request", "danger");
        });
    });
});

function alertMSG(msg, alertType) {
    const alertPlaceholder = document.getElementById('liveAlertPlaceholder')
    const appendAlert = (message, type) => {
        const wrapper = document.createElement('div')
        wrapper.innerHTML = [
          `<div class="alert alert-${type} alert-dismissible" role="alert" style="width: 400px;">`,
          `   <div>${message}</div>`,
          '   <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>',
          '</div>'
        ].join('')
      
        alertPlaceholder.append(wrapper)
    }

    setTimeout(function() {
        bootstrap.Alert.getOrCreateInstance(document.querySelector(".alert")).close();
    }, 2000)

    appendAlert(msg, alertType);
}