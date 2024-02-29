package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/go-resty/resty/v2"
	"github.com/gorilla/mux"
	"github.com/rifflock/lfshook"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var db *gorm.DB
var logger *logrus.Logger
var limiter = rate.NewLimiter(1, 3)

type User struct {
	gorm.Model
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type Country struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
}

type City struct {
	ID        uint   `json:"id"`
	CountryID uint   `json:"country_id"`
	Name      string `json:"name"`
}

type Hotel struct {
	ID     uint   `json:"id"`
	CityID uint   `json:"city_id"`
	Name   string `json:"name"`
}

type Tour struct {
	Country       string  `json:"country"`
	City          string  `json:"city"`
	Hotel         string  `json:"hotel"`
	DateArrival   string  `json:"date_arrival"`
	DateDeparture string  `json:"date_departure"`
	Adults        int     `json:"adults"`
	Children      int     `json:"children"`
	Price         int     `json:"price"`
	Img           string  `json:"img"`
	Temperature   float64 `json:"temperature"`
	Condition     string  `json:"condition"`
}

type WeatherData struct {
	Temperature float64 `json:"temperature"`
	Condition   string  `json:"condition"`
}

func initDB() {
	dsn := "host=localhost user=postgres password=123 dbname=registration sslmode=disable"
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	db.AutoMigrate(&User{})
}

func initLogger() {
	logger = logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	logFilePath := "log/logs.log"
	fileHook := lfshook.NewHook(lfshook.PathMap{
		logrus.InfoLevel:  logFilePath,
		logrus.ErrorLevel: logFilePath,
		logrus.FatalLevel: logFilePath,
		logrus.PanicLevel: logFilePath,
		logrus.DebugLevel: logFilePath,
	}, &logrus.JSONFormatter{})

	logger.AddHook(fileHook)
}

// create
func createUser(user *User) error {
	return db.Create(user).Error
}

func registration(w http.ResponseWriter, r *http.Request) {
	if !limiter.Allow() {
		responseError(w, http.StatusTooManyRequests, "Rate limit exceeded")
		return
	}

	var newUser User
	logger.WithFields(logrus.Fields{
		"module":   "main",
		"function": "registration",
	}).Info("User sent data")

	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&newUser)

	if err != nil {
		responseError(w, http.StatusBadRequest, "Invalid JSON message")
		return
	}

	emailPattern := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,4}$`)
	if !emailPattern.MatchString(newUser.Email) {
		responseError(w, http.StatusBadRequest, "Email does not meet requirements")
		return
	}

	if isEmailTaken(newUser.Email) {
		responseError(w, http.StatusConflict, "Email already taken")
		return
	}

	if isUsernameTaken(newUser.Username) {
		responseError(w, http.StatusConflict, "Username already taken")
		return
	}

	passwordPattern := regexp.MustCompile(`^[a-zA-Z\d]{8,}$`)
	if !passwordPattern.MatchString(newUser.Password) {
		responseError(w, http.StatusBadRequest, "Password does not meet requirements")
		return
	}

	newUser.Role = "user"

	err = createUser(&newUser)
	if err != nil {
		responseError(w, http.StatusInternalServerError, "Error creating user")
		return
	}

	logger.WithFields(logrus.Fields{
		"module":   "main",
		"function": "registration",
	}).Info("User successfully registered")
	responseSuccess(w, "User successfully registered", newUser)
}

func isUsernameTaken(username string) bool {
	var user User
	result := db.Where("username = ?", username).First(&user)
	return !errors.Is(result.Error, gorm.ErrRecordNotFound)
}

func isEmailTaken(email string) bool {
	var user User
	result := db.Where("email = ?", email).First(&user)
	return !errors.Is(result.Error, gorm.ErrRecordNotFound)
}

// read
func getUserByID(w http.ResponseWriter, r *http.Request) {
	logger.WithFields(logrus.Fields{
		"module":   "main",
		"function": "getUserByID",
	}).Info("Admin requested user data")

	userID := r.URL.Query().Get("id")
	id, err := strconv.Atoi(userID)
	if err != nil {
		responseError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	var user User
	err = db.First(&user, id).Error
	if err != nil {
		responseError(w, http.StatusNotFound, "User not found")
		return
	}

	logger.WithFields(logrus.Fields{
		"module":   "main",
		"function": "getUserByID",
	}).Info("Data was succesfully sent")

	responseSuccess(w, "success", user)
}

func getAllUsers(w http.ResponseWriter, r *http.Request) {
	logger.WithFields(logrus.Fields{
		"module":   "main",
		"function": "getAllUsers",
	}).Info("Admin requested all users' data")

	var users []User
	err := db.Find(&users).Error
	if err != nil {
		log.Fatal(err)
		responseError(w, http.StatusInternalServerError, "Error fetching users")
		return
	}

	logger.WithFields(logrus.Fields{
		"module":   "main",
		"function": "getAllUsers",
	}).Info("Data was succesfully sent")
	responseSuccess(w, "success", users)
}

// update
func updateUser(w http.ResponseWriter, r *http.Request) {
	logger.WithFields(logrus.Fields{
		"module":   "main",
		"function": "updateUser",
	}).Info("Admin updates user's data")

	var updatedUser User
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&updatedUser)

	if err != nil {
		responseError(w, http.StatusBadRequest, "Invalid JSON format")
		fmt.Println("Invalid JSON format")
		return
	}

	updatedUser.Role = "user"

	email := updatedUser.Email
	fmt.Println(email)
	err = db.Model(&User{}).Where("email = ?", email).Updates(&updatedUser).Error
	if err != nil {
		log.Fatal(err)
		responseError(w, http.StatusInternalServerError, "Error updating user")
		fmt.Println("Error Updating User")
		return
	}

	responseSuccess(w, "User updated successfully", updatedUser)
	logger.WithFields(logrus.Fields{
		"module":   "main",
		"function": "updateUser",
	}).Info("User updated sucessfully")
}

// delete
func deleteUser(w http.ResponseWriter, r *http.Request) {
	logger.WithFields(logrus.Fields{
		"module":   "main",
		"function": "deleteUser",
	}).Info("Admin deletes user's data")

	email := r.URL.Query().Get("email")
	err := db.Where("email = ?", email).Delete(&User{}).Error
	if err != nil {
		log.Fatal(err)
		responseError(w, http.StatusInternalServerError, "Error deleting user")
		return
	}
	logger.WithFields(logrus.Fields{
		"module":   "main",
		"function": "deleteUser",
	}).Info("User deleted successfully")
	responseSuccess(w, "User deleted successfully", email)
}

// login
func login(w http.ResponseWriter, r *http.Request) {
	if !limiter.Allow() {
		responseError(w, http.StatusTooManyRequests, "Rate limit exceeded")
		return
	}

	logger.WithFields(logrus.Fields{
		"module":   "main",
		"function": "login",
	}).Info("Login request")

	var loginData struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&loginData)
	if err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	login := loginData.Login
	password := loginData.Password
	fmt.Printf("Login request: Login: %s, Password: %s\n", login, password)

	if login != "" && password != "" {
		var user User
		result := db.Where("username = ?", login).First(&user)
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			responseError(w, http.StatusInternalServerError, fmt.Sprintf("User %s not found", login))
			return
		}

		isAdmin := checkUserRoleIsAdmin(login)

		if user.Password == password {
			res := map[string]interface{}{
				"status": 200,
				"admin":  isAdmin,
			}

			logger.WithFields(logrus.Fields{
				"module":   "main",
				"function": "login",
			}).Info("User successfully logged in")

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(res)

		} else {
			responseError(w, http.StatusUnauthorized, "Incorrect password")
		}
	} else {
		responseError(w, http.StatusUnauthorized, "Undefined or null login or password")
	}
}

func checkUserRoleIsAdmin(username string) bool {
	var user User
	result := db.Where("username = ?", username).First(&user)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return false
	}

	return user.Role == "admin"
}

// travel
func searchHandler(w http.ResponseWriter, r *http.Request) {
	if !limiter.Allow() {
		responseError(w, http.StatusTooManyRequests, "Rate limit exceeded")
		return
	}

	logger.WithFields(logrus.Fields{
		"module":   "main",
		"function": "searchHandler",
	}).Info("User requests tours data")

	queryParams := r.URL.Query()
	country := queryParams.Get("country")
	city := queryParams.Get("city")
	hotel := queryParams.Get("hotel")
	arrival := queryParams.Get("arrival")
	departure := queryParams.Get("departure")
	adultsStr := queryParams.Get("adults")
	childrenStr := queryParams.Get("children")
	sort := queryParams.Get("sort")
	page := queryParams.Get("page")

	limit := 4
	offset := 0

	var adults int
	if adultsStr != "" {
		var err error
		adults, err = strconv.Atoi(adultsStr)
		if err != nil {
			responseError(w, http.StatusBadRequest, "Invalid adults")
			return
		}
	} else {
		adults = 0
	}

	var children int
	if childrenStr != "" {
		var err error
		children, err = strconv.Atoi(childrenStr)
		if err != nil {
			responseError(w, http.StatusBadRequest, "Invalid children")
			return
		}
	} else {
		children = 0
	}

	if p, err := strconv.Atoi(page); err == nil && p > 1 {
		offset = (p - 1) * limit
	}

	matchingTours, err := findMatchingTours(sort, country, city, hotel, arrival, departure, adults, children, limit, offset)

	if err != nil {
		responseError(w, http.StatusBadRequest, "Error while parsing tours")
		return
	}

	if len(matchingTours) == 0 {
		responseError(w, http.StatusBadRequest, "No tours found")
	} else {
		logger.WithFields(logrus.Fields{
			"module":   "main",
			"function": "searchHandler",
		}).Info("Tours were found")

		responseSuccess(w, "Tours found", matchingTours)
	}
}

func findMatchingTours(sort, countryName, cityName, hotelName, arrival, departure string, adults, children, limit, offset int) ([]Tour, error) {
	var tours []Tour
	var country string
	var city string
	var hotel string
	query := db.Table("tours").
		Select("countries.name as country, cities.name as city, hotels.name as hotel, tours.date_arrival, tours.date_departure, tours.adults, tours.children, CAST(hotels.price * (tours.adults + 0.5 * tours.children) AS INTEGER) as price, hotels.img").
		Joins("JOIN hotels ON tours.hotel_id = hotels.id").
		Joins("JOIN cities ON tours.city_id = cities.id").
		Joins("JOIN countries ON tours.country_id = countries.id")

	if countryName != "" {
		country, err := getCountryByName(countryName)
		if err != nil {
			return tours, errors.New(err.Error())
		}

		query = query.Where("tours.country_id = ?", country.ID)
	}

	if cityName != "" {
		city, err := getCityByName(cityName)
		if err != nil {
			return tours, errors.New(err.Error())
		}

		query = query.Where("tours.city_id = ?", city.ID)
	}

	if hotelName != "" {
		hotel, err := getHotelByName(hotelName)
		if err != nil {
			return tours, errors.New(err.Error())
		}

		query = query.Where("tours.hotel_id = ?", hotel.ID)
	}

	if arrival != "" {
		query = query.Where("tours.date_arrival = ?", arrival)
	}

	if departure != "" {
		query = query.Where("tours.date_departure = ?", departure)
	}

	if adults != 0 {
		query = query.Where("tours.adults = ?", adults)
	}

	if children != 0 {
		query = query.Where("tours.children = ?", children)
	}

	if sort != "" {
		switch sort {
		case "asc":
			query = query.Order("price ASC")
		case "dsc":
			query = query.Order("price DESC")
		default:
			return nil, errors.New("invalid sort value")
		}
	}

	query = query.Offset(offset).Limit(limit)

	logger.WithFields(logrus.Fields{
		"country":   country,
		"city":      city,
		"hotel":     hotel,
		"arrival":   arrival,
		"departure": departure,
		"sort":      sort,
	}).Info("User request")

	if err := query.Find(&tours).Error; err != nil {
		return nil, fmt.Errorf("error executing database query: %v", err)
	}

	for i := range tours {
		weatherData := getWeatherByCity(tours[i].City)
		tours[i].Temperature = weatherData.Temperature
		tours[i].Condition = weatherData.Condition
	}

	return tours, nil
}

// weather
func getWeatherByCity(city string) WeatherData {
	apiKey := "7f1beacb3f1e4513aef90038241901"
	units := "metric"

	client := resty.New()
	response, err := client.R().
		SetQueryParams(map[string]string{
			"key":   apiKey,
			"units": units,
			"q":     city,
		}).
		Get("http://api.weatherapi.com/v1/current.json")

	if err != nil {
		fmt.Println("Error making the request:", err)
		return WeatherData{}
	}

	var data map[string]interface{}
	if err := json.Unmarshal(response.Body(), &data); err != nil {
		fmt.Println("Error decoding JSON:", err)
		return WeatherData{}
	}

	weatherData := WeatherData{
		Temperature: data["current"].(map[string]interface{})["temp_c"].(float64),
		Condition:   data["current"].(map[string]interface{})["condition"].(map[string]interface{})["text"].(string),
	}

	return weatherData
}

// data
func getData(w http.ResponseWriter, r *http.Request) {
	countries, err := getAllCountries()
	if err != nil {
		responseError(w, http.StatusInternalServerError, "Cannot access countries data")
		return
	}

	cities, err := getAllCities()
	if err != nil {
		responseError(w, http.StatusInternalServerError, "Cannot access cities data")
		return
	}

	hotels, err := getAllHotels()
	if err != nil {
		responseError(w, http.StatusInternalServerError, "Cannot access hotels data")
		return
	}

	var formattedCountries []map[string]interface{}
	for _, country := range countries {
		formattedCountry := map[string]interface{}{
			"id":   country.ID,
			"name": country.Name,
		}
		formattedCountries = append(formattedCountries, formattedCountry)
	}

	var formattedCities []map[string]interface{}
	for _, city := range cities {
		formattedCity := map[string]interface{}{
			"id":        city.ID,
			"countryID": city.CountryID,
			"name":      city.Name,
		}
		formattedCities = append(formattedCities, formattedCity)
	}

	var formattedHotels []map[string]interface{}
	for _, hotel := range hotels {
		formattedHotel := map[string]interface{}{
			"id":     hotel.ID,
			"cityID": hotel.CityID,
			"name":   hotel.Name,
		}
		formattedHotels = append(formattedHotels, formattedHotel)
	}

	data := map[string]interface{}{
		"countries": formattedCountries,
		"cities":    formattedCities,
		"hotels":    formattedHotels,
	}

	responseSuccess(w, "Data Sent", data)
}

func getAllCountries() ([]Country, error) {
	var countries []Country
	query := "SELECT id, name FROM countries"
	if err := db.Raw(query).Scan(&countries).Error; err != nil {
		return nil, err
	}
	return countries, nil
}

func getAllCities() ([]City, error) {
	var cities []City
	query := "SELECT id, name, country_id FROM cities"
	if err := db.Raw(query).Scan(&cities).Error; err != nil {
		return nil, err
	}
	return cities, nil
}

func getAllHotels() ([]Hotel, error) {
	var hotels []Hotel
	query := "SELECT id, name, city_id FROM hotels"
	if err := db.Raw(query).Scan(&hotels).Error; err != nil {
		return nil, err
	}
	return hotels, nil
}

func getItemByName(tableName, columnName, itemName string, item interface{}) error {
	return db.Table(tableName).Where(columnName+" = ?", itemName).First(item).Error
}

func getCountryByName(countryName string) (Country, error) {
	var country Country
	err := getItemByName("countries", "name", countryName, &country)
	return country, err
}

func getCityByName(cityName string) (City, error) {
	var city City
	err := getItemByName("cities", "name", cityName, &city)
	return city, err
}

func getHotelByName(hotelName string) (Hotel, error) {
	var hotel Hotel
	err := getItemByName("hotels", "name", hotelName, &hotel)
	return hotel, err
}

// serve pages
func serveLoginPage(w http.ResponseWriter, r *http.Request) {
	logger.WithFields(logrus.Fields{
		"module": "main",
	}).Info("User visits login page")
	filePath := filepath.Join("view", "login.html")
	http.ServeFile(w, r, filePath)
}

func serveRegistrationPage(w http.ResponseWriter, r *http.Request) {
	logger.WithFields(logrus.Fields{
		"module": "main",
	}).Info("User visits registration page")
	filePath := filepath.Join("view", "registration.html")
	http.ServeFile(w, r, filePath)
}

func serveAdminPage(w http.ResponseWriter, r *http.Request) {
	logger.WithFields(logrus.Fields{
		"module": "main",
	}).Info("Admin visits admin page")
	filePath := filepath.Join("view", "admin.html")
	http.ServeFile(w, r, filePath)
}

func serveHomePage(w http.ResponseWriter, r *http.Request) {
	logger.WithFields(logrus.Fields{
		"module": "main",
	}).Info("User visits home page")
	filePath := filepath.Join("view", "home.html")
	http.ServeFile(w, r, filePath)
}

func serveTravelPage(w http.ResponseWriter, r *http.Request) {
	logger.WithFields(logrus.Fields{
		"module": "main",
	}).Info("User visits travel page")
	filePath := filepath.Join("view", "index.html")
	http.ServeFile(w, r, filePath)
}

func serveToursPage(w http.ResponseWriter, r *http.Request) {
	logger.WithFields(logrus.Fields{
		"module": "main",
	}).Info("User visits tours page")
	filePath := filepath.Join("view", "search.html")
	http.ServeFile(w, r, filePath)
}

// JSON Response
func respondWithJSON(w http.ResponseWriter, statusCode int, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]interface{}{"status": statusCode, "message": message, "data": data})
}

func responseError(w http.ResponseWriter, statusCode int, message string) {
	respondWithJSON(w, statusCode, message, nil)
}

func responseSuccess(w http.ResponseWriter, message string, data interface{}) {
	respondWithJSON(w, http.StatusOK, message, data)
}

func main() {
	initDB()
	initLogger()

	r := mux.NewRouter()
	//create/register
	r.HandleFunc("/registration", registration).Methods("POST")
	r.HandleFunc("/registration", serveRegistrationPage).Methods("GET")

	//admin
	r.HandleFunc("/admin", serveAdminPage).Methods("GET")
	//admin router
	adminRouter := r.PathPrefix("/admin").Subrouter()
	adminRouter.HandleFunc("/updateUser", updateUser).Methods("PUT")
	adminRouter.HandleFunc("/deleteUser", deleteUser).Methods("DELETE")
	adminRouter.HandleFunc("/getUserByID", getUserByID).Methods("GET")
	adminRouter.HandleFunc("/getAllUsers", getAllUsers).Methods("GET")

	//login
	r.HandleFunc("/login", serveLoginPage).Methods("GET")
	r.HandleFunc("/login", login).Methods("POST")

	//homepage
	r.HandleFunc("/", serveHomePage).Methods("GET")
	//travel
	r.HandleFunc("/travel", serveTravelPage).Methods("GET")
	//travel router
	travelRouter := r.PathPrefix("/travel").Subrouter()
	travelRouter.HandleFunc("/tours", serveToursPage).Methods("GET")
	travelRouter.HandleFunc("/search", searchHandler).Methods("GET")
	travelRouter.HandleFunc("/data", getData).Methods("GET")

	//static files
	r.PathPrefix("/public/").Handler(http.StripPrefix("/public/", http.FileServer(http.Dir("public"))))
	fmt.Println("Server is listening on :8080...")
	http.ListenAndServe(":8080", r)
}
