package utils

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

var (
	currentFile   *os.File
	currentWriter *csv.Writer
	currentDate   string
	fileMutex     sync.Mutex
)

func InitCSV() error {
	fileMutex.Lock()
	defer fileMutex.Unlock()

	today := time.Now().Format("2006-01-02")
	if currentDate == today && currentFile != nil {
		return nil // Already initialized for today
	}

	if currentFile != nil {
		currentWriter.Flush()
		currentFile.Close()
	}

	fileName := fmt.Sprintf("clients_data/%s.csv", today)
	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed opening file: %w", err)
	}

	fileInfo, err := file.Stat()
	if err != nil {
		file.Close()
		return fmt.Errorf("failed getting file info: %w", err)
	}

	writer := csv.NewWriter(file)

	//write if the header is new

	if fileInfo.Size() == 0 {
		header := []string{"Timestamp", "Source IP", "Protocol", "Length", "Info"}
		if err := writer.Write(header); err != nil {
			file.Close()
			return fmt.Errorf("failed writing header to csv: %w", err)
		}
		writer.Flush()
	}

	currentFile = file
	currentWriter = writer
	currentDate = today

	return nil
}

func OpenCsvFile() *os.File {

	fileName := fmt.Sprintf("clients_data/%s.csv", time.Now().Format("2006-01-02"))
	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write CSV header if the file is new
	fileInfo, err := file.Stat()
	if err != nil {
		log.Fatalf("failed getting file info: %s", err)
	}
	if fileInfo.Size() == 0 {
		header := []string{"Timestamp", "Source IP", "Protocol", "Length", "Info"}
		if err := writer.Write(header); err != nil {
			log.Fatalf("failed writing header to csv: %s", err)
		}
	}

	return file
}

func WriteToCsv(record []string) error {
	fileMutex.Lock()
	defer fileMutex.Unlock()

	if err := initCSVInternal(); err != nil {
		log.Printf("Error initializing CSV: %v", err)
		return err
	}
	if err := currentWriter.Write(record); err != nil {
		log.Printf("Error writing to CSV: %v", err)
		return err
	}

	currentWriter.Flush()
	return nil
}

func initCSVInternal() error {
	today := time.Now().Format("2006-01-02")
	if currentDate == today && currentFile != nil {
		return nil // Already initialized for today
	}

	if currentFile != nil {
		currentWriter.Flush()
		currentFile.Close()
	}

	fileName := fmt.Sprintf("clients_data/%s.csv", today)
	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed opening file: %w", err)
	}
	fileInfo, err := file.Stat()
	if err != nil {
		file.Close()
		return fmt.Errorf("failed getting file info: %w", err)
	}

	writer := csv.NewWriter(file)
	//write if the header is new
	if fileInfo.Size() == 0 {
		header := []string{"Timestamp", "Source IP", "Protocol", "Length", "Info"}
		if err := writer.Write(header); err != nil {
			file.Close()
			return fmt.Errorf("failed writing header to csv: %w", err)
		}
		writer.Flush()
	}

	currentFile = file
	currentWriter = writer
	currentDate = today

	return nil

}

func CloseCSV() {
	fileMutex.Lock()
	defer fileMutex.Unlock()

	if currentWriter != nil {
		currentWriter.Flush()
	}
	if currentFile != nil {
		currentFile.Close()
		currentFile = nil
		currentWriter = nil
		currentDate = ""
	}
}
