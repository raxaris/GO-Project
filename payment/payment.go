package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/jung-kurt/gofpdf"
	"gopkg.in/gomail.v2"
)

type PaymentData struct {
	CardNumber string  `json:"cardNumber"`
	CardName   string  `json:"cardName"`
	ExpiryDate string  `json:"expiryDate"`
	CVV        string  `json:"cvv"`
	Price      float64 `json:"price"`
	Email      string  `json:"email"`
}

func processPaymentHandler(w http.ResponseWriter, r *http.Request) {
	var data PaymentData
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Print("Data", data)

	// Create PDF
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(40, 10, "Payment Receipt")
	pdf.Ln(10)
	pdf.SetFont("Arial", "", 12)
	pdf.Cell(40, 10, fmt.Sprintf("Amount: $%.2f", data.Price))
	pdf.Ln(10)
	pdf.Cell(40, 10, fmt.Sprintf("Date: %s", time.Now().Format("2006-01-02 15:04:05")))

	receiptDir := "./payment/receipts"
	if _, err := os.Stat(receiptDir); os.IsNotExist(err) {
		err = os.Mkdir(receiptDir, 0755)
		if err != nil {
			http.Error(w, "Error creating receipts directory", http.StatusInternalServerError)
			return
		}
	}

	// Use a unique file name for the PDF
	receiptFileName := filepath.Join(receiptDir, fmt.Sprintf("receipt_%d.pdf", time.Now().Unix()))
	err = pdf.OutputFileAndClose(receiptFileName)
	if err != nil {
		fmt.Print(err)
		http.Error(w, "Error generating PDF", http.StatusInternalServerError)
		return
	}
	// Read the PDF file into a buffer
	pdfFile, err := os.Open(receiptFileName)
	if err != nil {
		fmt.Print(err)
		http.Error(w, "Error opening generated PDF", http.StatusInternalServerError)
		return
	}
	defer pdfFile.Close()

	pdfBuffer := new(bytes.Buffer)
	_, err = pdfBuffer.ReadFrom(pdfFile)
	if err != nil {
		fmt.Print(err)
		http.Error(w, "Error reading generated PDF", http.StatusInternalServerError)
		return
	}

	// Send email with the PDF attached
	err = sendEmail(data.Email, pdfBuffer.Bytes())
	if err != nil {
		fmt.Print(err)
		http.Error(w, "Error sending email", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func sendEmail(recipient string, pdfData []byte) error {
	emailPassword := "nhmj faiz kysy owks"
	from := "waxansar99@gmail.com"

	m := gomail.NewMessage()
	m.SetHeader("From", from)
	m.SetHeader("To", recipient)
	m.SetHeader("Subject", "Your Payment Receipt")
	m.SetBody("text/plain", "Thank you for your payment. Please find the receipt attached.")

	m.Attach("receipt.pdf", gomail.SetCopyFunc(func(writer io.Writer) error {
		_, err := writer.Write(pdfData)
		fmt.Print(err)
		return err
	}))

	d := gomail.NewDialer("smtp.gmail.com", 587, from, emailPassword)

	if err := d.DialAndSend(m); err != nil {
		fmt.Print(err)
		return err
	}

	fmt.Print("Email sent")
	return nil
}
func main() {
	http.HandleFunc("/process-payment", processPaymentHandler)

	fmt.Println("Payment microservice is running on :8081...")
	http.ListenAndServe(":8081", nil)
}
