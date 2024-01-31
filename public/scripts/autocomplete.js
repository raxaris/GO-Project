let responseData = null;
let availableCountries = [];
let availableCities = [];
let availableHotels = [];
let countryResultBox;
let cityResultBox;
let hotelResultBox;
let countryInput;
let cityInput;
let hotelInput;


function fetchData(url) {
    return new Promise((resolve, reject) => {
        var xhr = new XMLHttpRequest();
        xhr.onreadystatechange = function () {
            if (xhr.readyState === 4) {
                if (xhr.status === 200) {
                    var data = JSON.parse(xhr.responseText);
                    resolve(data);
                } else {
                    reject('Failed to fetch data. Status code: ' + xhr.status);
                }
            }
        };
        xhr.open('GET', url, true);
        xhr.send();
    });
}

async function fetchDataAndProcess(url) {
    try {
        const data = await fetchData(url);
        console.log(url);
        responseData = data;
        console.log('Data:', data);

        availableCountries = responseData.countries.map(country => country.name);
        console.log(availableCountries);
        setupEventListeners();
    } catch (error) {
        console.error(error);
    }
}
function setupEventListeners() {
    countryResultBox = document.querySelector(".country-result-box");
    countryInput = document.getElementById("countryInput");

    countryInput.onkeyup = function () {
        let result = [];
        let input = countryInput.value;
        if (input.length) {
            result = availableCountries.filter((keyword) => {
                return keyword.toLowerCase().includes(input.toLowerCase());
            });
            console.log(result);
        }
        displayCountry(result);

        if (!result.length) {
            countryResultBox.innerHTML = '';
        }
    }

    cityResultBox = document.querySelector(".city-result-box");
    cityInput = document.getElementById("cityInput");

    cityInput.onkeyup = function () {
        let country = countryInput.value;
        if (!country.length) {
            showCustomAlert("Please enter a country");
            cityResultBox.innerHTML = '';
            return
        }

        updateAvailableCities(country);
        console.log(availableCities);
        
        let result = [];
        let input = cityInput.value;

        if (availableCities && availableCities.length) {
            if (input.length) {
                result = availableCities.filter((keyword) => {
                    return keyword.toLowerCase().includes(input.toLowerCase());
                });
                console.log(result);
            }
        } else {
            console.error('availableCities is not defined or empty');
        }
        displayCity(result);

        if (!result.length) {
            cityResultBox.innerHTML = '';
        }
    }

    hotelResultBox = document.querySelector(".hotel-result-box");
    hotelInput = document.getElementById("hotelInput");

    hotelInput.onkeyup = function () {
        let city = cityInput.value;
        if (!city.length) {
            showCustomAlert("Please enter a city");
            hotelResultBox.innerHTML = '';
            return
        }

        let result = [];
        let input = hotelInput.value;

        updateAvailableHotels(city);

        if (input.length) {
            result = availableHotels.filter((hotel) => {
                return hotel.toLowerCase().includes(input.toLowerCase());
            });
            console.log(result);
        }
        displayHotel(result);

        if (!result.length) {
            hotelResultBox.innerHTML = '';
        }
    }
}

function displayCountry(result){
    const content = result.map((list)=>{
        return "<li onclick=selectCountryInput(this)>" + list + "</li>";
    })

    countryResultBox.innerHTML = "<ul>" + content.join('') + "</ul>"
}

function selectCountryInput(list){
    countryInput.value = list.innerHTML;
    countryResultBox.innerHTML = ""
}

function displayCity(result){
    const content = result.map((list)=>{
        return "<li onclick=selectCityInput(this)>" + list + "</li>";
    })

    cityResultBox.innerHTML = "<ul>" + content.join('') + "</ul>"
}

function selectCityInput(list){
    cityInput.value = list.innerHTML;
    cityResultBox.innerHTML = ""
}

function displayHotel(result){
    const content = result.map((list)=>{
        return "<li onclick=selectHotelInput(this)>" + list + "</li>";
    })

    hotelResultBox.innerHTML = "<ul>" + content.join('') + "</ul>"
}

function selectHotelInput(list){
    hotelInput.value = list.innerHTML;
    hotelResultBox.innerHTML = ""
}

function updateAvailableCities(countryName) {
    const selectedCountry = responseData.countries.find(country => country.name === countryName);
    availableCities = selectedCountry ? selectedCountry.cities.map(city => city.name) : [];
}

function updateAvailableHotels(cityName) {
    const selectedCity = responseData.countries.flatMap(country => country.cities)
        .find(city => city.name === cityName);

    availableHotels = selectedCity ? selectedCity.hotels.map(hotel => hotel.name) : [];
}

fetchDataAndProcess('http://localhost:3000/travel/data');