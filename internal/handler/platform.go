package handler

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"

	"go-server/internal/config"
	"go-server/internal/crypto"
	"go-server/internal/database"
	"go-server/internal/service"
)

type PlatformHandler struct {
	cfg *config.Config
	db  *database.DB
}

func NewPlatformHandler(cfg *config.Config, db *database.DB) *PlatformHandler {
	return &PlatformHandler{cfg: cfg, db: db}
}

// POST /api/platform/v2/login (V2 格式) 和 /api/platform/login (V1 格式)
// V2: body = {"data": "{\"cipher\":\"...\",\"iv\":\"...\"}"}  整体加密
// V1: body = {"account": "{\"cipher\":\"...\",\"iv\":\"...\"}", "password": "{\"cipher\":\"...\",\"iv\":\"...\"}"}
func (h *PlatformHandler) Login(w http.ResponseWriter, r *http.Request) {
	deviceID := r.Header.Get("deviceid")
	if deviceID == "" {
		// 尝试不同的大小写
		deviceID = r.Header.Get("Deviceid")
	}
	if deviceID == "" {
		log.Println("[Login] Missing deviceid header")
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"code": "050208", "data": nil, "msg": "Missing deviceId"})
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"code": "050208", "data": nil, "msg": "Read body error"})
		return
	}
	defer r.Body.Close()

	log.Printf("[Login] deviceId=%s, body=%s", deviceID, string(body))

	var reqData map[string]interface{}
	if err := json.Unmarshal(body, &reqData); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"code": "050208", "data": nil, "msg": "Invalid JSON"})
		return
	}

	var decryptedAccount string

	// V2 格式：整体 data 字段加密
	if dataStr, ok := reqData["data"].(string); ok {
		var cipherData struct {
			Cipher string `json:"cipher"`
			IV     string `json:"iv"`
		}
		if err := json.Unmarshal([]byte(dataStr), &cipherData); err == nil && cipherData.Cipher != "" {
			plaintext, err := crypto.DecryptAES256GCM(cipherData.Cipher, deviceID, cipherData.IV)
			if err != nil {
				log.Printf("[Login] V2 decrypt failed: %v", err)
				writeJSON(w, http.StatusBadRequest, map[string]interface{}{"code": "050208", "data": nil, "msg": "Decrypt failed"})
				return
			}
			log.Printf("[Login] V2 decrypted: %s", string(plaintext))
			// 解密后的数据是 JSON，提取 account 和 otp 字段
			var loginData map[string]interface{}
			if err := json.Unmarshal(plaintext, &loginData); err == nil {
				log.Printf("[Login] V2 fields: %v", loginData)
				if acc, ok := loginData["account"].(string); ok {
					decryptedAccount = acc
				}
			}
			// 如果解密结果不是 JSON 或没有 account 字段，直接使用解密文本
			if decryptedAccount == "" {
				decryptedAccount = string(plaintext)
			}
		}
	}

	// V1 格式：account 和 password 分别加密
	if decryptedAccount == "" {
		if accountStr, ok := reqData["account"].(string); ok {
			var accountData struct {
				Cipher string `json:"cipher"`
				IV     string `json:"iv"`
			}
			if err := json.Unmarshal([]byte(accountStr), &accountData); err == nil {
				plaintext, err := crypto.DecryptAES256GCM(accountData.Cipher, deviceID, accountData.IV)
				if err != nil {
					log.Printf("[Login] V1 decrypt account failed: %v", err)
					writeJSON(w, http.StatusBadRequest, map[string]interface{}{"code": "050208", "data": nil, "msg": "Decrypt account failed"})
					return
				}
				decryptedAccount = string(plaintext)
			}
		}
	}

	if decryptedAccount == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"code": "050208", "data": nil, "msg": "No account data found"})
		return
	}

	log.Printf("[Login] account=%s, verifying OTP...", decryptedAccount)

	// OTP 验证：account 就是 OTP 代码（与 PHP 原始逻辑一致）
	// 优先本地 cotp 表验证，失败则回退到远程验证
	otpErr := h.db.VerifyOTP(decryptedAccount)
	if otpErr != "" {
		// 本地验证失败，显示具体错误
		log.Printf("[Login] OTP verification failed: %s", otpErr)
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": "050208", "data": nil, "msg": otpErr})
		return
	}
	log.Printf("[Login] OTP verified via local DB")

	// 从数据库获取活动服务器配置
	as, err := h.db.GetActivedServer()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"code": "050204", "data": nil, "msg": "DB error"})
		return
	}

	var serverResponse map[string]interface{}

	if as.ActiveBy == "ByID" {
		creds, err := h.db.GetServerCredentials(as.ServerID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"code": "050204", "data": nil, "msg": "Server credentials not found"})
			return
		}
		_ = creds
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"code": "050204", "data": nil, "msg": "ByID mode: configure target URL"})
		return
	}

	// ByToken 模式：构造静态响应
	areaCode, rgnCode := regionToAreaCode(as.Region)
	serverResponse = buildPlatformLoginResponse(as.Token, areaCode, rgnCode)

	data, _ := serverResponse["data"].(map[string]interface{})
	originalToken, _ := data["token"].(string)

	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	generatedToken := h.cfg.SiteSig + "V9" + hex.EncodeToString(randBytes)

	if err := h.db.InsertToken(generatedToken, originalToken); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"code": "050204", "data": nil, "msg": "Saving token error!"})
		return
	}

	data["token"] = generatedToken
	serverResponse["data"] = data

	// 记录登录地理信息
	userIP := service.GetClientIP(r)
	geoInfo := service.GetGeoInfo(userIP)
	go h.db.InsertLoginLog(decryptedAccount, userIP, geoInfo.City, geoInfo.Country, as.Region, "success", geoInfo.Lat, geoInfo.Lon)

	log.Printf("[Login] Success, token=%s", generatedToken)
	writeJSON(w, http.StatusOK, serverResponse)
}

func regionToAreaCode(region string) (string, string) {
	switch region {
	case "India":
		return "in", "in"
	case "Europe":
		return "eu", "fr"
	default: // Other, Singapore, etc.
		return "sg", "sg"
	}
}

func buildPlatformLoginResponse(token, areaCode, rgnCode string) map[string]interface{} {
	return map[string]interface{}{
		"code": "000000",
		"msg":  "Success",
		"data": map[string]interface{}{
			"token":       token,
			"areaCode":    areaCode,
			"regionCode":  rgnCode,
			"usrTypeCode": "after_sale",
			"toolId":      20,
			"toolCode":    "REALME_TOOLSHUB",
			"toolName":    "realme售后支持",
			"brand":       "realme",
			"businessList": []map[string]interface{}{
				{
					"businessId": 41, "businessCode": "UNLOCK_SRV", "businessName": "工模解密",
					"featureDTOs": []map[string]interface{}{
						{"featureId": 82, "featureCode": "server_wizards", "featureName": "服务向导"},
						{"featureId": 82, "featureCode": "server_wizards", "featureName": "服务向导"},
						{"featureId": 85, "featureCode": "ONLINE_UNLOCK", "featureName": "在线工模解密"},
						{"featureId": 86, "featureCode": "OFFLINE_UNLOCK", "featureName": "离线工模解密"},
					},
				},
				{
					"businessId": 39, "businessCode": "READBACK_SRV", "businessName": "小工具回读业务",
					"featureDTOs": []map[string]interface{}{
						{"featureId": 92, "featureCode": "READBACK_SRV", "featureName": "回读工具"},
					},
				},
				{
					"businessId": 36, "businessCode": "FLASH_SRV", "businessName": "刷机工具",
					"featureDTOs": []map[string]interface{}{
						{"featureId": 83, "featureCode": "flashtool_flashing", "featureName": "售后刷机"},
						{"featureId": 83, "featureCode": "flashtool_flashing", "featureName": "售后刷机"},
					},
				},
				{
					"businessId": 37, "businessCode": "DIAG_SRV", "businessName": "诊断插件",
					"featureDTOs": []map[string]interface{}{
						{"featureId": 84, "featureCode": "device_diagnosis", "featureName": "修前修后诊断"},
						{"featureId": 84, "featureCode": "device_diagnosis", "featureName": "修前修后诊断"},
					},
				},
			},
		},
	}
}
