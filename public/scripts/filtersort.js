let responseData = null;
let availableCountries = [];
let allCountries = []
let availableCities = [];
let allCities = []
let availableHotels = [];
let allHotels = []
let countryResultBox;
let cityResultBox;
let hotelResultBox;
let countryInput;
let cityInput;
let hotelInput;


function fetchData(url) {
    return new Promise((resolve, reject) => {
        fetch(url)
            .then(response => {
                if (!response.ok) {
                    throw new Error('Failed to fetch data. Status code: ' + response.status);
                }
                return response.json();
            })
            .then(data => resolve(data))
            .catch(error => reject(error));
    });
}

async function fetchDataAndProcess(url) {
    try {
        const data = await fetchData(url);
        console.log(url);
        //take data from data
        responseData = data.data;
        allCountries = responseData.countries;
        allCities = responseData.cities;
        allHotels = responseData.hotels;
        //check logs

        availableCountries = allCountries.map(country => country.name);

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


    sortingResultBox = document.querySelector(".sort-result-box");
    sortingInput = document.getElementById("sortInput");

    sortingInput.onclick = function () {
        let result = ["Ascending", "Descending"];
        displaySort(result);

    }
}

function displayCountry(result) {
    const content = result.map((list) => {
        return "<li onclick=selectCountryInput(this)>" + list + "</li>";
    })

    countryResultBox.innerHTML = "<ul>" + content.join('') + "</ul>"
}

function selectCountryInput(list) {
    countryInput.value = list.innerHTML;
    countryResultBox.innerHTML = ""
}

function displayCity(result) {
    const content = result.map((list) => {
        return "<li onclick=selectCityInput(this)>" + list + "</li>";
    })

    cityResultBox.innerHTML = "<ul>" + content.join('') + "</ul>"
}

function selectCityInput(list) {
    cityInput.value = list.innerHTML;
    cityResultBox.innerHTML = ""
}

function displayHotel(result) {
    const content = result.map((list) => {
        return "<li onclick=selectHotelInput(this)>" + list + "</li>";
    })

    hotelResultBox.innerHTML = "<ul>" + content.join('') + "</ul>"
}

function selectHotelInput(list) {
    hotelInput.value = list.innerHTML;
    hotelResultBox.innerHTML = ""
}

function displaySort(result) {
    const content = result.map((list) => {
        return "<li onclick=selectSortInput(this)>" + list + "</li>";
    })

    sortingResultBox.innerHTML = "<ul>" + content.join('') + "</ul>"
}

function selectSortInput(list) {
    sortingInput.value = list.innerHTML;
    sortingResultBox.innerHTML = ""
}


function updateAvailableCities(countryName) {
    const selectedCountry = allCountries.find(country => country.name === countryName);
    availableCities = selectedCountry ? allCities.filter(city => city.countryID === selectedCountry.id).map(city => city.name) : [];
    console.log("cities", availableCities);
}

function updateAvailableHotels(cityName) {
    const selectedCity = allCities.find(city => city.name === cityName);
    availableHotels = selectedCity ? allHotels.filter(hotel => hotel.cityID === selectedCity.id).map(hotel => hotel.name) : [];
    console.log("hotels", availableHotels);
}

document.addEventListener('DOMContentLoaded', function() {
    fetchDataAndProcess('https://go-project-nhcw.onrender.com/travel/data');
});