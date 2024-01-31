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

	"github.com/gorilla/mux"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var db *gorm.DB

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

func initDB() {
	dsn := "host=localhost user=postgres password=123 dbname=registration sslmode=disable"
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	db.AutoMigrate(&User{})
}

// create
func createUser(user *User) error {
	return db.Create(user).Error
}

func registration(w http.ResponseWriter, r *http.Request) {
	var newUser User

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

	responseSuccess(w, "success", user)
}

func getAllUsers(w http.ResponseWriter, r *http.Request) {
	var users []User
	err := db.Find(&users).Error
	if err != nil {
		log.Fatal(err)
		responseError(w, http.StatusInternalServerError, "Error fetching users")
		return
	}

	responseSuccess(w, "success", users)
}

// update
func updateUser(w http.ResponseWriter, r *http.Request) {

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
	fmt.Println("User updated successfully")
	fmt.Println(updatedUser.Email)
}

// delete
func deleteUser(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	fmt.Println(email)
	err := db.Where("email = ?", email).Delete(&User{}).Error
	if err != nil {
		log.Fatal(err)
		responseError(w, http.StatusInternalServerError, "Error deleting user")
		return
	}
	fmt.Println("User deleted successfully")
	responseSuccess(w, "User deleted successfully", email)
}

// login
func login(w http.ResponseWriter, r *http.Request) {

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
		isAdmin := checkUserRoleIsAdmin(login)

		res := map[string]interface{}{
			"status": 200,
			"admin":  isAdmin,
		}
		fmt.Print(res)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(res)
	} else {
		http.Error(w, "Undefined or null login or password", http.StatusUnauthorized)
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
	queryParams := r.URL.Query()

	country := queryParams.Get("country")
	city := queryParams.Get("city")
	hotel := queryParams.Get("hotel")
	arrival := queryParams.Get("arrival")
	departure := queryParams.Get("departure")
	adultsStr := queryParams.Get("adults")
	childrenStr := queryParams.Get("children")
	sort := queryParams.Get("sort")

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

	matchingTours, err := findMatchingTours(sort, country, city, hotel, arrival, departure, adults, children)

	if err != nil {
		responseError(w, http.StatusBadRequest, "Error while parsing tours")
		return
	}

	if len(matchingTours) == 0 {
		responseError(w, http.StatusBadRequest, "No tours found")
	} else {
		w.Header().Set("Content-Type", "application/json")
		responseSuccess(w, "Tours found", matchingTours)
	}
}

func findMatchingTours(sort, country, city, hotel, arrival, departure string, adults, children int) ([]map[string]interface{}, error) {
	var tours []map[string]interface{}

	query := db.Table("tours").
		Select("tours.*, countries.name as country_name, cities.name as city_name, hotels.name as hotel_name, hotels.price as hotel_price, hotels.img as hotel_img").
		Joins("JOIN countries ON tours.country_id = countries.id").
		Joins("JOIN cities ON tours.city_id = cities.id").
		Joins("JOIN hotels ON tours.hotel_id = hotels.id")

	if country != "" {
		query = query.Where("countries.name = ?", country)
	}
	if city != "" {
		query = query.Where("cities.name = ?", city)
	}
	if hotel != "" {
		query = query.Where("hotels.name = ?", hotel)
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
			query = query.Order("hotel_price ASC")
		case "desc":
			query = query.Order("hotel_price DESC")
		default:
			return nil, errors.New("invalid sort value")
		}
	}

	if err := query.Find(&tours).Error; err != nil {
		return nil, err
	}

	for i := range tours {
		tours[i]["total_price"] = calculateTotalPrice(tours[i]["hotel_price"].(int), tours[i]["adults"].(int), tours[i]["children"].(int))
	}

	return tours, nil
}

func calculateTotalPrice(hotelPrice, adults, children int) int {
	totalPrice := hotelPrice * (adults + children/2)
	return totalPrice
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

// serve pages
func serveLoginPage(w http.ResponseWriter, r *http.Request) {
	filePath := filepath.Join("view", "login.html")
	http.ServeFile(w, r, filePath)
}

func serveRegistrationPage(w http.ResponseWriter, r *http.Request) {
	filePath := filepath.Join("view", "registration.html")
	http.ServeFile(w, r, filePath)
}

func serveAdminPage(w http.ResponseWriter, r *http.Request) {
	filePath := filepath.Join("view", "admin.html")
	http.ServeFile(w, r, filePath)
}

func serveHomePage(w http.ResponseWriter, r *http.Request) {
	filePath := filepath.Join("view", "home.html")
	http.ServeFile(w, r, filePath)
}

func serveTravelPage(w http.ResponseWriter, r *http.Request) {
	filePath := filepath.Join("view", "index.html")
	http.ServeFile(w, r, filePath)
}

func serveToursPage(w http.ResponseWriter, r *http.Request) {
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
