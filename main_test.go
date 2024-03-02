package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/tebeka/selenium"
	"github.com/tebeka/selenium/chrome"
)

func TestGenerateRandomCode(t *testing.T) {
	code := generateRandomCode()

	if len(code) != 6 {
		t.Errorf("Expected code length of 6, got %d", len(code))
	}

	_, err := strconv.Atoi(code)
	if err != nil {
		t.Errorf("Expected code to contain only digits, got %s", code)
	}

	t.Log("Test passed: TestGenerateRandomCode")
}

func TestGetTour(t *testing.T) {
	initLogger()
	initDB()

	request, _ := http.NewRequest("GET", "http://localhost:8080/travel/search?country=USA&city=Miami&hotel=Fontainebleau%20Miami%20Beach&arrival=2024-03-09&departure=2024-03-14&adults=1&children=2", nil)

	response := httptest.NewRecorder()

	searchHandler(response, request)

	if response.Code != http.StatusOK {
		t.Errorf("Incorrect status code. Expected: %d, Got: %d", http.StatusOK, response.Code)
	}

	contentType := response.Header().Get("Content-Type")
	expectedContentType := "application/json"
	if contentType != expectedContentType {
		t.Errorf("Incorrect Content-Type. Expected: %s, Got: %s", expectedContentType, contentType)
	}

	type TourData struct {
		Country       string `json:"country"`
		City          string `json:"city"`
		Hotel         string `json:"hotel"`
		DateArrival   string `json:"date_arrival"`
		DateDeparture string `json:"date_departure"`
		Adults        int    `json:"adults"`
		Children      int    `json:"children"`
		Price         int    `json:"price"`
		Img           string `json:"img"`
	}
	type ToursResponse struct {
		Data    []TourData `json:"data"`
		Message string     `json:"message"`
		Status  int        `json:"status"`
	}

	var responseData ToursResponse
	err := json.NewDecoder(response.Body).Decode(&responseData)
	if err != nil {
		t.Errorf("Failed to parse response JSON: %v", err)
	}

	expectedDataCount := 1
	if len(responseData.Data) != expectedDataCount {
		t.Errorf("Incorrect number of tours. Expected: %d, Got: %d", expectedDataCount, len(responseData.Data))
	}

	expectedTour := TourData{
		Country:       "USA",
		City:          "Miami",
		Hotel:         "Fontainebleau Miami Beach",
		DateArrival:   "2024-03-09T00:00:00Z",
		DateDeparture: "2024-03-14T00:00:00Z",
		Adults:        1,
		Children:      2,
		Price:         1800,
		Img:           "https://dynamic-media-cdn.tripadvisor.com/media/photo-o/0e/f6/17/f0/miami-beach.jpg?w=700\u0026h=-1\u0026s=1",
	}
	if !reflect.DeepEqual(responseData.Data[0], expectedTour) {
		t.Errorf("Incorrect tour data. Expected: %+v, Got: %+v", expectedTour, responseData.Data[0])
	}

	expectedMessage := "Tours found"
	if responseData.Message != expectedMessage {
		t.Errorf("Incorrect message. Expected: %s, Got: %s", expectedMessage, responseData.Message)
	}

	expectedStatus := http.StatusOK
	if responseData.Status != expectedStatus {
		t.Errorf("Incorrect status. Expected: %d, Got: %d", expectedStatus, responseData.Status)
	}
	t.Log("Test passed: TestGetTour")
}

func TestGetTourEndToEnd(t *testing.T) {

	caps := selenium.Capabilities{"browserName": "chrome"}
	chromeCaps := chrome.Capabilities{
		Path: "",
	}
	caps.AddChrome(chromeCaps)

	wd, err := selenium.NewRemote(caps, "")
	if err != nil {
		t.Fatal(err)
	}
	defer wd.Quit()

	if err := wd.Get("http://localhost:8080/travel/tours"); err != nil {
		t.Fatal(err)
	}

	title, err := wd.Title()
	if err != nil {
		t.Fatal(err)
	}
	if title != "DNK" {
		t.Errorf("Expected title 'DNK', but got '%s'", title)
	}

	searchInput, err := wd.FindElement(selenium.ByID, "countryInput")
	if err != nil {
		t.Fatal(err)
	}
	searchInput.SendKeys("USA")

	searchButton, err := wd.FindElement(selenium.ByClassName, "filter-box-poppins blue")
	if err != nil {
		t.Fatal(err)
	}
	searchButton.Click()

	time.Sleep(5 * time.Second)

	searchResults, err := wd.FindElements(selenium.ByClassName, "row p-0")
	if err != nil {
		t.Fatal(err)
	}
	if len(searchResults) == 0 {
		t.Error("No search results found")
	}
	t.Log("Test passed: TestGetTourEndToEnd")
}
