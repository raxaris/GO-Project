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
	if r.Method != http.MethodPut {
		http.Error(w, "Only PUT requests are allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.URL.Query().Get("id")
	if userID == "" {
		responseError(w, http.StatusBadRequest, "User ID is empty")
		return
	}

	id, err := strconv.ParseInt(userID, 10, 64)
	if err != nil {
		responseError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	var updatedUser User
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&updatedUser)

	if err != nil {
		responseError(w, http.StatusBadRequest, "Invalid JSON format")
		return
	}

	err = db.Model(&User{}).Where("id = ?", id).Updates(updatedUser).Error
	if err != nil {
		log.Fatal(err)
		responseError(w, http.StatusInternalServerError, "Error updating user")
		return
	}

	responseSuccess(w, "User updated successfully", updatedUser)
}

// delete
func deleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Only DELETE requests are allowed", http.StatusMethodNotAllowed)
		return
	}

	email := r.URL.Query().Get("email")

	err := db.Delete(&User{}, email).Error
	if err != nil {
		log.Fatal(err)
		responseError(w, http.StatusInternalServerError, "Error deleting user")
		return
	}

	responseSuccess(w, "User deleted successfully", email)
}

// login
func login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
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
				"status": "success",
				"admin":  isAdmin,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(res)
		} else {
			http.Error(w, "Undefined or null login or password", http.StatusUnauthorized)
		}
	} else {
		http.Error(w, "Only POST requests are allowed", http.StatusMethodNotAllowed)
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
	//read
	r.HandleFunc("/getUserByID", getUserByID).Methods("GET")
	r.HandleFunc("/updateUser", updateUser).Methods("PUT")
	r.HandleFunc("/getAllUsers", getAllUsers).Methods("GET")

	//update
	r.HandleFunc("/updateUser", updateUser).Methods("PUT")

	//delete
	r.HandleFunc("/deleteUser", deleteUser).Methods("DELETE")

	//login
	r.HandleFunc("/login", serveLoginPage).Methods("GET")
	r.HandleFunc("/login", login).Methods("POST")

	//admin
	r.HandleFunc("/admin", serveAdminPage).Methods("GET")
	//static files
	r.PathPrefix("/public/").Handler(http.StripPrefix("/public/", http.FileServer(http.Dir("public"))))
	fmt.Println("Server is listening on :8080...")
	http.ListenAndServe(":8080", r)
}
