package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

func encryptAES256GCM(plaintext []byte, keyB64 string) (cipherB64, ivB64 string, err error) {
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return "", "", fmt.Errorf("decode key: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", fmt.Errorf("new cipher: %v", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", fmt.Errorf("new gcm: %v", err)
	}
	nonce := make([]byte, aesGCM.NonceSize())
	rand.Read(nonce)
	sealed := aesGCM.Seal(nil, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(sealed), base64.StdEncoding.EncodeToString(nonce), nil
}

func main() {
	serverURL := "https://opluspro.top/api/platform/v2/login"
	if len(os.Args) > 1 {
		serverURL = os.Args[1]
	}

	// OTP code as account (matches PHP logic)
	otp := "02003F622FB0D99CC51D1870F965D61D"
	if len(os.Args) > 2 {
		otp = os.Args[2]
	}

	// Generate a random deviceid (base64)
	devBytes := make([]byte, 32)
	rand.Read(devBytes)
	deviceID := base64.StdEncoding.EncodeToString(devBytes)

	// Build login JSON
	loginData := map[string]string{
		"account":  otp,
		"password": "test123",
		"mac":      "00-11-22-33-44-55",
	}
	loginJSON, _ := json.Marshal(loginData)
	fmt.Printf("Plaintext: %s\n", loginJSON)
	fmt.Printf("DeviceID:  %s\n", deviceID)

	// Encrypt
	cipherText, iv, err := encryptAES256GCM(loginJSON, deviceID)
	if err != nil {
		fmt.Printf("Encrypt error: %v\n", err)
		return
	}

	// Build inner data JSON
	innerData := map[string]string{
		"cipher": cipherText,
		"iv":     iv,
	}
	innerJSON, _ := json.Marshal(innerData)

	// Build outer request body
	reqBody := map[string]string{
		"data": string(innerJSON),
	}
	reqJSON, _ := json.Marshal(reqBody)
	fmt.Printf("Request:   %s\n\n", reqJSON)

	// Send request
	req, _ := http.NewRequest("POST", serverURL, bytes.NewReader(reqJSON))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Deviceid", deviceID)
	req.Header.Set("Lang", "zh-CN")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("Request error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Status: %d\n", resp.StatusCode)
	fmt.Printf("Response: %s\n", string(body))
}
