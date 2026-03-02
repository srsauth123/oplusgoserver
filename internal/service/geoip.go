package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type GeoInfo struct {
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
}

func GetGeoInfo(ip string) *GeoInfo {
	resp, err := http.Get(fmt.Sprintf("http://ip-api.com/json/%s", ip))
	if err != nil {
		return &GeoInfo{Country: "Unknown", City: "Unknown"}
	}
	defer resp.Body.Close()

	var geo GeoInfo
	if err := json.NewDecoder(resp.Body).Decode(&geo); err != nil {
		return &GeoInfo{Country: "Unknown", City: "Unknown"}
	}
	return &geo
}

func CountryFlagEmoji(countryCode string) string {
	if countryCode == "" {
		return ""
	}
	code := strings.ToUpper(countryCode)
	var flag strings.Builder
	for _, c := range code {
		flag.WriteRune(rune(127397 + c))
	}
	return flag.String()
}

func GetClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		parts := strings.Split(ip, ",")
		return strings.TrimSpace(parts[0])
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	// 去掉端口
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}
