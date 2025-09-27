package geolocate

import (
	"fmt"
	"net"

	"github.com/oschwald/maxminddb-golang"
)

// CityRecord represents the structure of city data from MaxMind DB
type CityRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`

	Country struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`

	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

// LocationInfo holds the geolocation data
type LocationInfo struct {
	City      string  `json:"city"`
	Country   string  `json:"country"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// String returns a formatted string representation
func (l *LocationInfo) String() string {
	return fmt.Sprintf("City: %s, Country: %s, Coordinates: %.4f, %.4f", 
		l.City, l.Country, l.Latitude, l.Longitude)
}

// LocateIP returns city, country, and coordinates for an IP address
func LocateIP(ipStr string) (*LocationInfo, error) {
	// Parse IP address
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	// Open database
	db, err := maxminddb.Open("GeoLite2-City.mmdb")
	if err != nil {
		return nil, fmt.Errorf("failed to open MaxMind DB: %w", err)
	}
	defer db.Close()

	// Lookup IP
	var record CityRecord
	err = db.Lookup(ip, &record)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup IP %s: %w", ipStr, err)
	}

	// Extract data
	info := &LocationInfo{
		Latitude:  record.Location.Latitude,
		Longitude: record.Location.Longitude,
	}

	// Get city name (English)
	if name, exists := record.City.Names["en"]; exists {
		info.City = name
	}

	// Get country name (English)
	if name, exists := record.Country.Names["en"]; exists {
		info.Country = name
	}

	return info, nil
}