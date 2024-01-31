async function renderCart(data) {
    const tours = data;
    console.log("tourdata", data);
    const tourContainer = document.querySelector(".tours");

    tourContainer.innerHTML = "";

    const weatherPromises = tours.map(async (tour) => {

        const weatherData = await getWeatherData(tour.city);

        const tourElement = document.createElement("div");
        tourElement.classList.add("row", "p-0");

        tourElement.innerHTML = `
            <div class="inner-list mb-3">
                <div class="list-items">
                    <div class="tour-container row">
                        <div class="tour-image col-3">
                            <img src="${tour.img}" style="max-width: 300px;">
                        </div>
                        <div class="tour-info col-9">
                            <div class="item-hotel"><span class="item-brand">${tour.hotel}</span></div>
                            <div class="item-location">
                                <span class="tour-country">${tour.country}</span>,
                                <span class="tour-city"> ${tour.city}</span>,
                                <span class="tour-condition"> ${weatherData.condition}</span> <span class="tour-temp"> ${weatherData.temperature}°C</span>
                            </div>
                            <div class="item-date">
                                <div class="arrival">Arrival Date: <span class="date-arrival">${tour.arrival}</span></div>    
                                <div class="departure">Departure Date: <span class="date-arrival">${tour.departure}</span></div>    
                            </div>  
                            <div class="people">
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
    });

    await Promise.all(weatherPromises);

    const amountOfTours = document.getElementById("amountOfTours");
    amountOfTours.textContent = tours.length;
    const plural = document.getElementById("plural");
    plural.textContent = tours.length === 1 ? "" : "s";
}

async function renderPage() {
    try {
        const queryString = window.location.search;
        console.log(queryString);
        const serverURL = `http://localhost:8080/travel/search${queryString}`;
        console.log(serverURL);
        
        const data = await getDataFromServer(serverURL);
        console.log("query Data", data);
        renderCart(data);
    } catch (error) {
        console.error("Error rendering page:", error);
    }
}

window.addEventListener('load', async () => {
    await renderPage();
});

async function getDataFromServer(url) {
    try {
        const response = await fetch(url);

        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }

        const data = await response.json();
        return data;
    } catch (error) {
        console.error("Error fetching data:", error);
        throw error;
    }
}

async function getWeatherData(city){
    try {
        const serverURL = "http://localhost:8080/travel/weather";
        const response = await fetch(`${serverURL}?city=${city}`);
        const data = await response.json();
        console.log(data);
        return data;
    } catch (error) {
        console.error('Error fetching weather data:', error);
    }
}