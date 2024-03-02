function setInitialFilterValues() {
    const urlParams = new URLSearchParams(window.location.search);

    const countryInput = document.getElementById("countryInput");
    const countryParam = urlParams.get("country");
    if (countryParam) {
        countryInput.value = countryParam;
    }

    const cityInput = document.getElementById("cityInput");
    const cityParam = urlParams.get("city");
    if (cityParam) {
        cityInput.value = cityParam;
    }


    const hotelInput = document.getElementById("hotelInput");
    const hotelParam = urlParams.get("hotel");
    if (hotelParam) {
        hotelInput.value = hotelParam;
    }

    const dateRangeInput = document.getElementById("dateRange");
    const dateRangeParam = urlParams.get("dateRange");
    if (dateRangeParam) {
        dateRangeInput.value = dateRangeParam;
    }

    const adultsInput = document.getElementById("adults");
    const adultsParam = urlParams.get("adults");
    if (adultsParam) {
        adultsInput.value = adultsParam;
    }

    const childrenInput = document.getElementById("children");
    const childrenParam = urlParams.get("children");
    if (childrenParam) {
        childrenInput.value = childrenParam;
    }
}
async function renderPagination(){
    const paginationContainer = document.querySelector(".pagination")
    paginationContainer.innerHTML = `
    <nav class="pagination-outer" aria-label="Page navigation">
        <ul class="pagination">
            <li class="page-item">
                <a href="#" class="page-link" aria-label="Previous">
                    <span aria-hidden="true">«</span>
                </a>
            </li>
            <li class="page-item"><a class="page-link" href="#">1</a></li>
            <li class="page-item"><a class="page-link" href="#">2</a></li>
            <li class="page-item active"><a class="page-link" href="#">3</a></li>
            <li class="page-item"><a class="page-link" href="#">4</a></li>
            <li class="page-item"><a class="page-link" href="#">5</a></li>
            <li class="page-item">
                <a href="#" class="page-link" aria-label="Next">
                    <span aria-hidden="true">»</span>
                </a>
            </li>
        </ul>
    </nav>` 
}
async function renderCart(data) {
    const tours = data;
    const tourContainer = document.querySelector(".tours");
    tourContainer.innerHTML = "";
    for (const tour of tours) {
        const tourElement = document.createElement("div");
        tourElement.classList.add("row", "p-0");

        tourElement.innerHTML = `
            <div class="inner-list mb-3">
                <div class="list-items">
                    <div class="tour-container row">
                        <div class="tour-image col-3">
                            <img src="${tour.img}" style="width: 300px; height: 200px">
                        </div>
                        <div class="tour-info col-9">
                            <div class="item-hotel"><span class="item-hotel">${tour.hotel}</span></div>
                            <div class="item-location">
                                <span class="tour-country">${tour.country}</span>,
                                <span class="tour-city"> ${tour.city}</span>,
                                <span class="tour-condition"> ${configureCondition(tour.condition)}</span> <span class="tour-temp"> ${tour.temperature}°C</span>
                            </div>
                            <div class="item-date">
                                <div class="arrival"><span class="date-arrival">${formatDateString(tour.date_arrival)}</span> 🛬</div>    
                                <div class="departure"><span class="date-arrival">${formatDateString(tour.date_departure)}</span> 🛫 </div>    
                            </div>  
                            <div class="adultsandchildren">
                                <div class="adults">&#x1F465:  ${tour.adults}</div> 
                                ${tour.children > 0 ? `<div class="children">&#x1F9D2: ${tour.children}</div>` : ''}
                            </div>
                            <div class="item-price">Total Price: <span class="tour-price">${tour.price}</span>$</div>
                        </div> 
                    </div>
                </div>
                <hr class="solid liner mt-4">
            </div>
        `;

        tourContainer.appendChild(tourElement);
    }

    const amountOfTours = document.getElementById("amountOfTours");
    amountOfTours.textContent = tours.length;
    const plural = document.getElementById("plural");
    plural.textContent = tours.length === 1 ? "" : "s";
}


async function renderPage(page) {
    try {
        simulateLoading();
        document.getElementById('loadingBarContainer').style.display = 'block';
        const queryString = window.location.search;
        let serverURL;
        if(queryString){
            serverURL = `https://go-project-nhcw.onrender.com/travel/search${queryString}&page=${page}`;
        } else {
            serverURL = `https://go-project-nhcw.onrender.com/travel/search?page=${page}`
        }
        console.log(serverURL);
        const data = await getDataFromServer(serverURL);
        document.getElementById('loadingBarContainer').style.display = 'none';
        console.log("query Data", data.data);
        
        renderCart(data.data);
    } catch (error) {
        alertMSG("Error rendering page", "danger")
        document.getElementById('loadingBarContainer').style.display = 'none';
    }
}

window.addEventListener('load', async () => {
    setInitialFilterValues();
    await renderPage(1);
});

async function getDataFromServer(url) {
    try {
        const response = await fetch(url);

        if (!response.ok) {
            alertMSG("No tours available", "danger")
        }

        const data = await response.json();
        return data;
    } catch (error) {
        alertMSG("Error fetching data", "danger")
        document.getElementById('loadingBarContainer').style.display = 'none';
        throw error;
    }
}

function configureCondition(condition) {
    condition = condition.toLowerCase();

    if (condition.includes("snow")) {
        return "&#x1F328";
    } else if (condition.includes("mist") || condition.includes("fog")) {
        return "&#x1F32B;";
    } else if (condition.includes("sunny") || condition.includes("clear")) {
        return "&#x2600";
    } else if (condition.includes("cloud") || condition.includes("overcast")) {
        return "&#x2601";
    } else if (condition.includes("rain") || condition.includes("thunder")) {
        return "&#x1F327;";
    } else {
        return "&#x2600";
    }
}

function formatDateString(dateString) {
    const options = { day: 'numeric', month: 'long', year: 'numeric' };
    const formattedDate = new Date(dateString).toLocaleDateString('en-US', options);
    return formattedDate;
}

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