async function submitPayment() {
    event.preventDefault(); 
    const form = document.getElementById('formPayment');
    const formData = new FormData(form);

    const data = {
        cardNumber: formData.get('cardNumber'),
        cardName: formData.get('cardName'),
        expiryDate: formData.get('expiryDate'),
        cvv: formData.get('cvv'),
    };

    // Получение orderID из URL
    const urlPath = window.location.pathname.split('/');
    const orderID = urlPath[urlPath.length - 1];

    fetch(`http://localhost:8080/travel/order/${orderID}`, {
        method: "POST",
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
    .then(data => {
        console.log(data)
        if (data.status === 200 || data.status === "success") {
            alertMSG(data.message, "");
            window.location.href = "/";
        } else {
            alertMSG(data.message, "danger");
        }
    })
    .catch(error => {
        console.error("An error occurred while processing your request:", error);
    });
}

document.addEventListener('DOMContentLoaded', function () {
    const formElement = document.getElementById('formPayment');
    console.log(formElement);
    formElement.addEventListener('submit', async (event) => {
        event.preventDefault();

        const formData = new FormData(form);

        const data = {
            cardNumber: formData.get('cardNumber'),
            cardName: formData.get('cardName'),
            expiryDate: formData.get('expiryDate'),
            cvv: formData.get('cvv'),
        };
        console.log(data)
        // Получение orderID из URL
        const urlPath = window.location.pathname.split('/');
        const orderID = urlPath[urlPath.length - 1];

        fetch(`http://localhost:8080/travel/order/${orderID}`, {
            method: "POST",
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 200 || data.status === "success") {
                alertMSG(data.message, "danger");
                window.location.href = "/";
            } else {
                alertMSG(data.message, "danger");
            }
        })
        .catch(error => {
            console.error("An error occurred while processing your request:", error);
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