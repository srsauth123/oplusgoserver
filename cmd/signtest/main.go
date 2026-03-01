package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	// account = OTP 代码（Go 服务器会验证 OTP 后替换为 workid 再转发）
	otp := "A7AC15B96EA77310D1302EC591FC72"
	if len(os.Args) > 2 {
		otp = os.Args[2]
	}

	signData := map[string]interface{}{
		"account":       otp,
		"agreementVer":  "48",
		"chipSn":        "RCA6JN65LN89PVPZ",
		"daVer":         "0",
		"deviceType":    "1",
		"diskId":        "",
		"extIp":         "192.168.1.21",
		"lockVer":       "1",
		"loginType":     "1",
		"mac":           "70-85-C2-C6-CE-2E",
		"mainPlatform":  "MTK",
		"metaVer":       "0",
		"newProjectNo":  "24702",
		"newRemake":     "???",
		"newSwNameSign": "bc4d98103ec2faed54ac6e7f60a3b4a6c0630ad34a0337fa1911ca3a6c4ba158",
		"nvCheck":       true,
		"nvCode":        "10011010",
		"nvPlatForm":    "mt6768",
		"oldProjectNo":  "24702",
		"oldSwNameSign": "b4e9929e4fdc3ee8355d919293242bad61583918bbd56aaa2d1e7bd0ecb21e8b",
		"plVer":         "1",
		"projectNumber": "24702",
		"randomNum":     "9b5fe92e9b5fe92e",
		"readWriteMode": "W",
		"subPlatform":   "MT6768",
		"toolDeviceId":  "78968c739c6017da2e17e4f9e00f043381178b58eec58e178a283ab15021441d",
		"toolHash":      "01bcba980933a314e3efffa2afcdb846df6b53e4ec306aea70b81fd5e56418d2",
		"toolVersion":   "2.9.76",
		"version":       "0",
		"workerOrder":   "",
	}

	// 生成随机 AES-256 key (32 bytes) 作为 deviceid
	keyBytes := make([]byte, 32)
	rand.Read(keyBytes)
	deviceID := base64.StdEncoding.EncodeToString(keyBytes)

	// 生成随机 nonce (12 bytes)
	nonceBytes := make([]byte, 12)
	rand.Read(nonceBytes)
	ivB64 := base64.StdEncoding.EncodeToString(nonceBytes)

	// JSON 编码
	plaintext, _ := json.Marshal(signData)
	fmt.Println("=== 签名测试 ===")
	fmt.Printf("OTP (account): %s\n", otp)
	fmt.Printf("DeviceId:      %s\n\n", deviceID)

	// AES-256-GCM 加密
	block, _ := aes.NewCipher(keyBytes)
	aesGCM, _ := cipher.NewGCMWithNonceSize(block, len(nonceBytes))
	sealed := aesGCM.Seal(nil, nonceBytes, plaintext, nil)
	cipherB64 := base64.StdEncoding.EncodeToString(sealed)

	// 构建请求 body
	innerData := map[string]string{"cipher": cipherB64, "iv": ivB64}
	innerJSON, _ := json.Marshal(innerData)
	body := map[string]interface{}{
		"businessId": "FLASH_SIGN",
		"data":       string(innerJSON),
	}
	bodyJSON, _ := json.Marshal(body)

	// 目标: 我们的 Go 服务器（由它做 OTP 验证 + 替换 workid + 加密转发到 gsmtgt.me）
	// 用法: go run . <server_url> [otp] [token]
	targetURL := "https://your-server.com/api/sign/sign"
	if len(os.Args) > 1 {
		targetURL = os.Args[1]
	}

	token := "TEST_TOKEN"
	if len(os.Args) > 3 {
		token = os.Args[3]
	}

	fmt.Printf("=== 发送到 Go 服务器 ===\n")
	fmt.Printf("URL:      %s\n", targetURL)
	fmt.Printf("Deviceid: %s\n", deviceID)
	fmt.Printf("Token:    %s\n\n", token)

	fmt.Println("Go 服务器处理流程:")
	fmt.Println("  1. 用 Deviceid 解密 body")
	fmt.Printf("  2. 验证 OTP: %s\n", otp)
	fmt.Println("  3. 替换 account → workid (从面板配置读取)")
	fmt.Println("  4. 用 cert 凭证重新加密")
	fmt.Println("  5. 转发到 sign_url (从面板配置读取)")
	fmt.Println()

	// 发送请求（模拟客户端 → 我们的 Go 服务器）
	req, _ := http.NewRequest("POST", targetURL, strings.NewReader(string(bodyJSON)))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Deviceid", deviceID)
	req.Header.Set("Token", token)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	fmt.Printf("=== 响应 (HTTP %d) ===\n%s\n", resp.StatusCode, string(respBody))
}
