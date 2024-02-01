# DNK Tour

Welcome to the DNK Tour - Travel Agency Application – your one-stop solution for planning and booking personalized tours around the world.
## Requirements
This project is compatible with Node.js version 20.10.0. Ensure that you have Node.js installed with a version matching or later than 20.10.0 before proceeding with the installation and execution of the project.
## Project Structure

- **Routes**: The `routes` folder contains the routers for different functionalities. Notable ones are:
  - `travelRouter.js`: Manages routes related to tour searches, data retrieval, weather information, and logging.

- **Public**: The `public` folder stores static assets such as CSS scripts and images.

- **View**: The `view` folder contains HTML files for different pages of the application.
- **Data Storage**:
  - `data.json`: Stores data related to tours, countries, cities, hotels, and prices.
  - `logs.json`: Maintains a log of historical search queries.
  - `users.json`: Stores users data, such as username, email, password.
  - `package-lock.json`: Captures dependency versions to ensure consistent installations.
  

- **Server**:
 - `server.js`: Main server file that handles routing, static files, and server initialization.


## Installation
### 1. Clone the Repository:
```bash
git clone https://github.com/raxaris/travel-agency.git
```
### 2. Navigate to the Project Directory:
```bash
cd travel-agency
```
### 3. Install Dependencies:
```go
go mod download
```
### 4. Run the Application:
```go
go run main.go
```
### 5. Open in Browser:
Visit http://localhost:3000 to explore the Travel Agency Application.
