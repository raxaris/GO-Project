package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var db *gorm.DB

type User struct {
	gorm.Model
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
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

func createUser(user *User) error {
	return db.Create(user).Error
}

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

func deleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Only DELETE requests are allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.URL.Query().Get("id")
	id, err := strconv.Atoi(userID)
	if err != nil {
		responseError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	err = db.Delete(&User{}, id).Error
	if err != nil {
		log.Fatal(err)
		responseError(w, http.StatusInternalServerError, "Error deleting user")
		return
	}

	responseSuccess(w, "User deleted successfully", userID)
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

func isUsernameTaken(username string) bool {
	var user User
	result := db.Where("username = ?", username).First(&user)
	return result.RowsAffected > 0
}

func isEmailTaken(email string) bool {
	var user User
	result := db.Where("email = ?", email).First(&user)
	return result.RowsAffected > 0
}

func handleRegistration(w http.ResponseWriter, r *http.Request) {
	var newUser User
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&newUser)

	if err != nil {
		responseError(w, http.StatusBadRequest, "Invalid JSON message")
		return
	}

	if isUsernameTaken(newUser.Username) {
		responseError(w, http.StatusConflict, "Username already taken")
		return
	}

	if isEmailTaken(newUser.Email) {
		responseError(w, http.StatusConflict, "Email already taken")
		return
	}

	err = createUser(&newUser)
	if err != nil {
		responseError(w, http.StatusInternalServerError, "Error creating user")
		return
	}

	responseSuccess(w, "User successfully registered", newUser)
}

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

	http.HandleFunc("/register", handleRegistration)
	http.HandleFunc("/getUserByID", getUserByID)
	http.HandleFunc("/updateUser", updateUser)
	http.HandleFunc("/deleteUser", deleteUser)
	http.HandleFunc("/getAllUsers", getAllUsers)

	fmt.Println("Server is listening on :8080...")
	http.ListenAndServe(":8080", nil)
}
