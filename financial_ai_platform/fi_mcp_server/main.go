package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
)

var (
	store       = sessions.NewCookieStore([]byte("fi-mcp-dev-secret-key"))
	testDataDir = "./test_data_dir"
)

type LoginRequest struct {
	PhoneNumber string `json:"phoneNumber"`
	OTP         string `json:"otp"`
}

type LoginResponse struct {
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	AccessToken string `json:"accessToken,omitempty"`
	SessionID   string `json:"sessionId,omitempty"`
}

func main() {
	// Load environment variables
	err := godotenv.Load("../.env")
	if err != nil {
		log.Println("Warning: .env file not found, using default values")
	}

	port := os.Getenv("FI_MCP_PORT")
	if port == "" {
		port = "3001"
	}

	router := mux.NewRouter()
	router.Use(corsMiddleware)

	// Public routes
	router.HandleFunc("/", serveLoginPage).Methods("GET")
	router.HandleFunc("/login", loginHandler).Methods("POST")
	router.HandleFunc("/login-success", serveSuccessPage).Methods("GET")
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

	// Protected routes
	protected := router.PathPrefix("/api").Subrouter()
	protected.Use(authMiddleware)
	protected.HandleFunc("/fetch-net-worth", fetchNetWorthHandler).Methods("GET")
	protected.HandleFunc("/fetch-credit-report", fetchCreditReportHandler).Methods("GET")
	protected.HandleFunc("/fetch-epf-details", fetchEPFDetailsHandler).Methods("GET")
	protected.HandleFunc("/fetch-mutual-fund-transactions", fetchMutualFundTransactionsHandler).Methods("GET")
	protected.HandleFunc("/fetch-bank-transactions", fetchBankTransactionsHandler).Methods("GET")
	protected.HandleFunc("/fetch-stock-transactions", fetchStockTransactionsHandler).Methods("GET")



	log.Printf("🐹 Fi MCP Server starting on port %s", port)
	log.Printf("📁 Using test data directory: %s", testDataDir)
	log.Fatal(http.ListenAndServe(":"+port, router))
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Phone-Number")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check session
		session, err := store.Get(r, "fi-mcp-session")
		if err == nil && session.Values["authenticated"] == true {
			next.ServeHTTP(w, r)
			return
		}

		// Check X-Phone-Number header as fallback
		if phone := r.Header.Get("X-Phone-Number"); phone != "" {
			// Auto-login with header
			session, _ := store.Get(r, "fi-mcp-session")
			session.Values["authenticated"] = true
			session.Values["phoneNumber"] = phone
			session.Save(r, w)
			next.ServeHTTP(w, r)
			return
		}

		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

func getPhoneNumber(r *http.Request) string {
	// Check header first
	if phone := r.Header.Get("X-Phone-Number"); phone != "" {
		return phone
	}

	// Check session
	session, err := store.Get(r, "fi-mcp-session")
	if err != nil {
		return ""
	}
	if phone, ok := session.Values["phoneNumber"].(string); ok {
		return phone
	}
	return ""
}

func loadJSONData(phoneNumber, filename string) (map[string]interface{}, error) {
	filePath := filepath.Join(testDataDir, phoneNumber, filename)
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var jsonData map[string]interface{}
	err = json.Unmarshal(data, &jsonData)
	return jsonData, err
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var loginReq LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check if user directory exists
	userDir := filepath.Join(testDataDir, loginReq.PhoneNumber)
	if _, err := os.Stat(userDir); os.IsNotExist(err) {
		response := LoginResponse{
			Success: false,
			Message: "Phone number not found in test scenarios",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	// Create session
	session, _ := store.Get(r, "fi-mcp-session")
	session.Values["authenticated"] = true
	session.Values["phoneNumber"] = loginReq.PhoneNumber
	session.Save(r, w)

	response := LoginResponse{
		Success:     true,
		Message:     "Login successful",
		AccessToken: fmt.Sprintf("fi-mcp-token-%s", loginReq.PhoneNumber),
		SessionID:   fmt.Sprintf("session-%s", loginReq.PhoneNumber),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func serveLoginPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./static/login.html")
}

func serveSuccessPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./static/success.html")
}

// API Handlers
func fetchNetWorthHandler(w http.ResponseWriter, r *http.Request) {
	phoneNumber := getPhoneNumber(r)
	if phoneNumber == "" {
		http.Error(w, "Phone number required", http.StatusUnauthorized)
		return
	}

	data, err := loadJSONData(phoneNumber, "fetch_net_worth.json")
	if err != nil {
		http.Error(w, "Net worth data not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func fetchCreditReportHandler(w http.ResponseWriter, r *http.Request) {
	phoneNumber := getPhoneNumber(r)
	if phoneNumber == "" {
		http.Error(w, "Phone number required", http.StatusUnauthorized)
		return
	}

	data, err := loadJSONData(phoneNumber, "fetch_credit_report.json")
	if err != nil {
		http.Error(w, "Credit report data not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func fetchEPFDetailsHandler(w http.ResponseWriter, r *http.Request) {
	phoneNumber := getPhoneNumber(r)
	if phoneNumber == "" {
		http.Error(w, "Phone number required", http.StatusUnauthorized)
		return
	}

	data, err := loadJSONData(phoneNumber, "fetch_epf_details.json")
	if err != nil {
		http.Error(w, "EPF details not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func fetchMutualFundTransactionsHandler(w http.ResponseWriter, r *http.Request) {
	phoneNumber := getPhoneNumber(r)
	if phoneNumber == "" {
		http.Error(w, "Phone number required", http.StatusUnauthorized)
		return
	}

	data, err := loadJSONData(phoneNumber, "fetch_mf_transactions.json")
	if err != nil {
		http.Error(w, "Mutual fund transactions not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func fetchBankTransactionsHandler(w http.ResponseWriter, r *http.Request) {
    phoneNumber := getPhoneNumber(r)
    if phoneNumber == "" {
        http.Error(w, "Phone number required", http.StatusUnauthorized)
        return
    }
    data, err := loadJSONData(phoneNumber, "fetch_bank_transactions.json")
    if err != nil {
        http.Error(w, "Bank transactions not found", http.StatusNotFound)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(data)
}

func fetchStockTransactionsHandler(w http.ResponseWriter, r *http.Request) {
    phoneNumber := getPhoneNumber(r)
    if phoneNumber == "" {
        http.Error(w, "Phone number required", http.StatusUnauthorized)
        return
    }
    data, err := loadJSONData(phoneNumber, "fetch_stock_transactions.json")
    if err != nil {
        http.Error(w, "Stock transactions not found", http.StatusNotFound)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(data)
}





