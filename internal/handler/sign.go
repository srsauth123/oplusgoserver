package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"go-server/internal/config"
	"go-server/internal/crypto"
	"go-server/internal/database"
	"go-server/internal/service"
)

type SignHandler struct {
	cfg      *config.Config
	db       *database.DB
	telegram *service.TelegramService
	tools    *ToolsHandler
}

func NewSignHandler(cfg *config.Config, db *database.DB, tg *service.TelegramService) *SignHandler {
	return &SignHandler{cfg: cfg, db: db, telegram: tg}
}

func (h *SignHandler) SetToolsHandler(t *ToolsHandler) {
	h.tools = t
}

// POST /api/sign/sign
// 支持两种输入格式：
// 1. 加密格式: {"businessId":"FLASH_SIGN","data":"{\"cipher\":\"...\",\"iv\":\"...\"}"}
// 2. 原始 JSON: {"account":"OTP","chipSn":"...","mainPlatform":"MTK",...}
func (h *SignHandler) Sign(w http.ResponseWriter, r *http.Request) {
	deviceID := r.Header.Get("Deviceid")
	clientToken := r.Header.Get("Token")

	if clientToken == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": "050204", "msg": "Token is required"})
		return
	}

	rawInput, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"code": "050500", "msg": "Read body error"})
		return
	}
	defer r.Body.Close()

	var reqBody map[string]interface{}
	json.Unmarshal(rawInput, &reqBody)

	var signRawData map[string]interface{}
	isEncrypted := false

	// 检测是加密格式还是原始 JSON
	if dataStr, ok := reqBody["data"].(string); ok {
		// 加密格式：解析 cipher/iv
		var cipherData map[string]string
		json.Unmarshal([]byte(dataStr), &cipherData)
		cipherText := cipherData["cipher"]
		iv := cipherData["iv"]

		if deviceID == "" || cipherText == "" || iv == "" {
			writeJSON(w, http.StatusOK, map[string]interface{}{"code": "000002", "msg": "Decryption failed"})
			return
		}

		plaintext, err := crypto.DecryptAES256GCM(cipherText, deviceID, iv)
		if err != nil {
			log.Printf("[Sign] Decrypt failed: %v", err)
			writeJSON(w, http.StatusOK, map[string]interface{}{"code": "000002", "msg": "Decryption failed"})
			return
		}
		json.Unmarshal(plaintext, &signRawData)
		isEncrypted = true
	} else if _, ok := reqBody["account"]; ok {
		// 原始 JSON 格式：直接使用
		signRawData = reqBody
		isEncrypted = false
	} else {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": "000002", "msg": "Invalid request format"})
		return
	}

	account, _ := signRawData["account"].(string)
	chipSN := getStr(signRawData, "chipSn")
	if chipSN == "" {
		chipSN = getStr(signRawData, "chip_sn")
	}
	projectNumber := getStr(signRawData, "projectNumber")
	mainPlatform := getStr(signRawData, "mainPlatform")
	if mainPlatform == "" {
		mainPlatform = getStr(signRawData, "main_platform")
	}
	subPlatform := getStr(signRawData, "subPlatform")
	if subPlatform == "" {
		subPlatform = getStr(signRawData, "sub_platform")
	}

	log.Printf("[Sign] account=%s chipSn=%s platform=%s encrypted=%v", account, chipSN, mainPlatform, isEncrypted)

	// Step 2: 验证 OTP（account 就是 OTP）
	if account == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": "050204", "msg": "Account is empty"})
		return
	}
	if otpErr := h.db.VerifyOTP(account); otpErr != "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": "050204", "msg": otpErr})
		return
	}

	// Step 3: 从 actived_server 读取转发配置（workid、sign_url、region 均可在面板设置）
	activedSrv, err := h.db.GetActivedServer()
	if err != nil {
		log.Printf("[Sign] GetActivedServer error: %v", err)
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": "050500", "msg": "Active server config not found"})
		return
	}
	region := activedSrv.Region
	if region == "" {
		region = "Eu"
	}

	// 解密后确定签名类型并路由
	// 优先级: 1.解密参数中的 signType  2.服务端 sign_mode 配置  3.自动检测
	signMode := h.detectSignMode(signRawData, activedSrv.SignMode)
	log.Printf("[Sign] 签名类型判定: %s | account=%s chipSn=%s", signMode, account, chipSN)

	if signMode == "rcsm" {
		if h.tools == nil {
			writeJSON(w, http.StatusOK, map[string]interface{}{"code": "050500", "msg": "RCSM handler not initialized"})
			return
		}
		h.signViaRCSM(w, r, signRawData, account, chipSN, mainPlatform, subPlatform, projectNumber, clientToken)
		return
	}

	// 从 cert 表取加密凭证
	cert, err := h.db.GetCertByRegion(region)
	if err != nil {
		log.Printf("[Sign] cert region=%s not found: %v", region, err)
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": "050500", "msg": "Cert config not found"})
		return
	}

	// 从 new_server 取 token（用于上游认证）
	var upstreamToken string
	serverCfg, err := h.db.GetNewServerByType("Realme")
	if err == nil {
		upstreamToken = serverCfg.Token
	}
	if upstreamToken == "" {
		if orig, err := h.db.FindOriginalToken(clientToken); err == nil {
			upstreamToken = orig
		} else {
			upstreamToken = clientToken
		}
	}

	// Step 4: 替换 account → workid（从面板配置读取）
	workid := activedSrv.WorkID
	if workid == "" {
		workid = "NBSQ17RNA130T"
	}
	signRawData["account"] = workid

	// Step 5: 用 cert 的 DeviceId + IV 重新加密
	signBodyJSON, _ := json.Marshal(signRawData)
	encryptedData, err := crypto.EncryptAES256GCM(signBodyJSON, cert.DeviceId, cert.IV)
	if err != nil {
		log.Printf("[Sign] Re-encrypt error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"code": "050500", "msg": "Encrypt error"})
		return
	}

	// 构建转发 body（外层固定 businessId=FLASH_SIGN）
	newCipherData := map[string]string{"cipher": encryptedData, "iv": cert.IV}
	newCipherJSON, _ := json.Marshal(newCipherData)
	newBody := map[string]interface{}{"businessId": "FLASH_SIGN", "data": string(newCipherJSON)}
	newBodyJSON, _ := json.Marshal(newBody)

	// Step 6: 确定转发目标 URL
	targetURL := activedSrv.SignURL
	if targetURL == "" {
		targetURL = "https://gsmtgt.me/api/sign/sign"
	}
	if fwdURL, err := h.db.GetSignForwardURL(region); err == nil && fwdURL != "" {
		targetURL = fwdURL
	}

	// Step 7: 使用 cert headers 转发
	log.Printf("[Sign] → 转发到 %s | region=%s account=%s chipSn=%s project=%s", targetURL, region, account, chipSN, projectNumber)
	fwdReq, _ := http.NewRequest("POST", targetURL, strings.NewReader(string(newBodyJSON)))
	fwdReq.Header.Set("Content-Type", "application/json; charset=utf-8")
	fwdReq.Header.Set("deviceId", cert.DeviceId)
	fwdReq.Header.Set("cipherInfo", cert.CipherInfo)
	fwdReq.Header.Set("token", upstreamToken)
	fwdReq.Header.Set("lang", "zh-CN")

	httpClient := &http.Client{Timeout: 60 * time.Second}
	resp, err := httpClient.Do(fwdReq)
	if err != nil {
		log.Printf("[Sign] ✗ 上游请求失败: %v", err)
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": "050500", "msg": "Server Offline"})
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	response := string(respBody)
	log.Printf("[Sign] ← 上游响应(%d): %s", resp.StatusCode, truncStr(response, 800))

	// 日志 & Telegram 通知
	userIP := service.GetClientIP(r)
	geoInfo := service.GetGeoInfo(userIP)
	flag := ""
	if geoInfo.Status == "success" {
		flag = service.CountryFlagEmoji(geoInfo.CountryCode)
	}

	go h.telegram.SendSignNotification(
		mainPlatform, subPlatform, chipSN, account,
		userIP, geoInfo.City, geoInfo.Country, flag,
		time.Now().Format("2006-01-02 15:04:05"),
		response,
	)

	var responseData map[string]interface{}
	if err := json.Unmarshal(respBody, &responseData); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": "050500", "msg": "Server Offline"})
		return
	}

	code, _ := responseData["code"].(string)
	msg, _ := responseData["msg"].(string)

	// 上游返回 OTP 相关错误时，对客户端隐藏细节，显示为服务器离线
	if code == "050209" || (code == "050204" && strings.Contains(strings.ToLower(msg), "otp")) {
		log.Printf("[Sign] 上游OTP错误(%s): %s → 返回Server Offline", code, msg)
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": "050500", "msg": "Server Offline", "data": nil})
		return
	}

	// 写入 sign_logs（含完整响应 + lat/lon）
	go h.db.InsertSignLog(mainPlatform, subPlatform, chipSN, account, userIP,
		geoInfo.City, geoInfo.Country, region, code, msg, response, geoInfo.Lat, geoInfo.Lon)

	// 写入 flashlog
	go h.db.InsertFlashLog(account, "", chipSN, projectNumber, code, msg, "Realme", mainPlatform)

	// 成功后标记 OTP 已用 + 标记 token 已用
	if code == "000000" {
		h.db.MarkOTPUsed(account)
		h.db.MarkTokenUsed(clientToken)
	}

	writeRaw(w, http.StatusOK, "application/json", respBody)
}

// POST /api/sign/login
// toolCode = OTP 代码，验证后返回工具权限列表
func (h *SignHandler) Login(w http.ResponseWriter, r *http.Request) {
	rawInput, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

	var data map[string]interface{}
	if err := json.Unmarshal(rawInput, &data); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "error", "message": "Invalid JSON"})
		return
	}

	toolCode, ok := data["toolCode"].(string)
	if !ok || toolCode == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "error", "message": "No otp code provided in the request."})
		return
	}

	// 用 toolCode 作为 OTP 验证（与 Sign() 使用相同的本地验证）
	if otpErr := h.db.VerifyOTP(toolCode); otpErr != "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": "050204", "data": nil, "msg": otpErr})
		return
	}

	// 读取当前活动区域配置
	activedSrv, _ := h.db.GetActivedServer()
	areaCode := "Eu"
	regionCode := "De"
	if activedSrv != nil && activedSrv.Region != "" {
		areaCode = activedSrv.Region
		// 区域代码映射
		regionMap := map[string]string{"Eu": "De", "India": "In", "China": "Cn", "Singapore": "Sg", "Europe": "De", "Other": "De"}
		if rc, ok := regionMap[activedSrv.Region]; ok {
			regionCode = rc
		}
	}

	log.Printf("[SignLogin] toolCode=%s verified, region=%s", toolCode, areaCode)

	loginResp := fmt.Sprintf(`{
   "code" : "000000",
   "data" : {
      "areaCode" : "%s",
      "brand" : "oppo",
      "businessList" : [
         {"businessCode":"DIAG_SRV","businessId":23,"businessName":"诊断业务","featureDTOs":[{"featureCode":"device_diagnosis","featureId":65,"featureName":"修前&&修后"},{"featureCode":"offline_scan","featureId":66,"featureName":"脱机扫码"}]},
         {"businessCode":"CLEARDATA_SRV","businessId":25,"businessName":"数据双清","featureDTOs":[{"featureCode":"CLEAR_DEVICE_DATA","featureId":68,"featureName":"清除设备数据"}]},
         {"businessCode":"ONEPLUSFLASH_SRV","businessId":31,"businessName":"小工具一加OFP整包刷机业务","featureDTOs":[{"featureCode":"oneplusflash_plugin","featureId":76,"featureName":"一加OFP整包刷机功能"}]},
         {"businessCode":"WRITEIMEIANDFLAG_SRV","businessId":27,"businessName":"写号及国家码工具","featureDTOs":[{"featureCode":"WRITEIMEIANDFLAG","featureId":71,"featureName":"写号及标志位"}]},
         {"businessCode":"POWEROFF_DIAG_SRV","businessId":26,"businessName":"不开机诊断","featureDTOs":[{"featureCode":"Poweroff_diagnosis","featureId":69,"featureName":"不开机诊断权限开关"}]},
         {"businessCode":"CALIB_SRV","businessId":24,"businessName":"器件校准","featureDTOs":[{"featureCode":"calib_procedure","featureId":67,"featureName":"器件校准"}]},
         {"businessCode":"FLASH_SRV","businessId":29,"businessName":"刷机插件","featureDTOs":[{"featureCode":"ftflash_pkg_manage","featureId":72,"featureName":"固件包管理"},{"featureCode":"flashtool_basic_flashing","featureId":74,"featureName":"基础刷机功能"}]},
         {"businessCode":"READBACK_SRV","businessId":28,"businessName":"小工具回读业务","featureDTOs":[{"featureCode":"readback_plugin","featureId":70,"featureName":"回读功能"}]},
         {"businessCode":"UNLOCK_SRV","businessId":14,"businessName":"工模解密","featureDTOs":[{"featureCode":"OFFLINE_UNLOCK","featureId":46,"featureName":"离线解密"},{"featureCode":"ONLINE_UNLOCK","featureId":47,"featureName":"在线解密"}]}
      ],
      "regionCode" : "%s",
      "token" : "TGT-147194-4IKfMrAtjRa5jfu0hlLceQqYYLJACAuEAHjW7Qbi7uLT6LRUYH-SIAM",
      "toolCode" : "TOOLSHUB",
      "toolId" : 13,
      "toolName" : "O+支持",
      "usrTypeCode" : "after_sale"
   },
   "msg" : "Success"
}`, areaCode, regionCode)

	writeRaw(w, http.StatusOK, "application/json", []byte(loginResp))
}

// detectSignMode 根据解密后的参数和服务端配置确定签名类型
// 优先级: 1.参数命名格式(snake_case/camelCase) 2.显式signType 3.sign_mode配置 4.自动检测
func (h *SignHandler) detectSignMode(signRawData map[string]interface{}, configMode string) string {
	// 1. 检测参数命名格式
	//    RCSM 数据使用 snake_case: chip_sn, country_code, new_project_no ...
	//    新版数据使用 camelCase:   chipSn,  nvCode,       newProjectNo ...
	if _, ok := signRawData["chip_sn"]; ok {
		log.Printf("[Sign] 检测到 snake_case 参数(chip_sn) → RCSM")
		return "rcsm"
	}

	// 2. 客户端在加密数据中显式指定 signType
	if st, ok := signRawData["signType"].(string); ok && (st == "rcsm" || st == "new") {
		log.Printf("[Sign] 从解密参数检测到 signType=%s", st)
		return st
	}

	// 3. 服务端配置的 sign_mode（面板设置的强制模式）
	if configMode == "rcsm" || configMode == "new" {
		return configMode
	}

	// 4. auto: 有可用 RCSM token → RCSM，否则转发
	if h.hasRCSMTokens() {
		return "rcsm"
	}

	return "new"
}

// hasRCSMTokens 检查是否有任何可用的 RCSM token（用于 auto 模式判断）
func (h *SignHandler) hasRCSMTokens() bool {
	if h.tools == nil {
		return false
	}
	apis := h.tools.getRCSMSignAPIs()
	for _, api := range apis {
		if api.URL == "" || api.Secret == "" {
			continue
		}
		if tok, err := h.db.GetRCSMToken(api.Server); err == nil && tok != "" {
			return true
		}
	}
	return false
}

// signViaRCSM 将请求桥接到 RCSM 官方签名流程
// 支持两种输入格式:
//   - snake_case (RCSM原生): 直接使用，仅覆盖 token/mac
//   - camelCase (新版工具):  camelCase → snake_case 字段映射后发送
func (h *SignHandler) signViaRCSM(w http.ResponseWriter, r *http.Request,
	signRawData map[string]interface{},
	account, chipSN, mainPlatform, subPlatform, projectNumber, clientToken string) {

	log.Printf("[Sign-RCSM] 桥接→RCSM | account=%s chipSn=%s platform=%s", account, chipSN, mainPlatform)

	var rcsmData map[string]interface{}

	if _, isSnakeCase := signRawData["chip_sn"]; isSnakeCase {
		// 已是 snake_case RCSM 格式，直接复制使用
		rcsmData = make(map[string]interface{})
		for k, v := range signRawData {
			rcsmData[k] = v
		}
		delete(rcsmData, "account")
	} else {
		// camelCase → snake_case 转换
		lockVer := getStr(signRawData, "lockVer")
		if lockVer == "" {
			lockVer = "0"
		}
		countryCode := getStr(signRawData, "nvCode")
		if countryCode == "" {
			countryCode = "0000000"
		}

		rcsmData = map[string]interface{}{
			"chip_sn":          chipSN,
			"disk_id":          "SOID8Y88",
			"ext_ip":           "0.0.0.0",
			"lock_ver":         lockVer,
			"device_type":      "1",
			"login_type":       "1",
			"main_platform":    mainPlatform,
			"meta_ver":         "0",
			"new_project_no":   getStr(signRawData, "newProjectNo"),
			"new_sw_name_sign": getStr(signRawData, "newSwNameSign"),
			"old_project_no":   getStr(signRawData, "oldProjectNo"),
			"old_sw_name_sign": getStr(signRawData, "oldSwNameSign"),
			"random_num":       getStr(signRawData, "randomNum"),
			"read_write_mode":  getStr(signRawData, "readWriteMode"),
			"sub_platform":     subPlatform,
			"nv_check":         getAny(signRawData, "nvCheck", false),
			"country_code":     countryCode,
			"nv_platForm":      getStr(signRawData, "nvPlatForm"),
			"da_ver":           getStr(signRawData, "daVer"),
			"version":          "0",
			"workerorder":      "C00003639001-R251208005",
		}
	}

	apis := h.tools.getRCSMSignAPIs()
	var lastMessage string
	var lastServer string
	triedCount := 0
	skipCount := 0

	for _, api := range apis {
		if api.URL == "" || api.Secret == "" {
			continue
		}

		token, err := h.db.GetRCSMToken(api.Server)
		if err != nil || token == "" {
			log.Printf("[Sign-RCSM] Skip %s: no token", api.Server)
			skipCount++
			continue
		}

		triedCount++

		serverMac := "00-E0-4C-73-E7-47"
		if creds, credErr := h.db.GetRCSMCredentials(api.Server); credErr == nil && creds.Mac != "" {
			serverMac = creds.Mac
		}
		rcsmData["mac"] = serverMac
		rcsmData["token"] = token

		result := h.tools.sendRCSMSignRequest(rcsmData, api.Secret, api.URL, "1")
		if result == nil {
			log.Printf("[Sign-RCSM] ✗ %s: 请求失败", api.Server)
			continue
		}

		data, ok := result["Data"].(map[string]interface{})
		if !ok {
			continue
		}
		resp, ok := data["response"].(map[string]interface{})
		if !ok {
			continue
		}

		encrypt, _ := resp["encrypt"].(string)
		message, _ := resp["message"].(string)
		lastMessage = message
		lastServer = api.Server

		if encrypt != "" && message == "" {
			log.Printf("[Sign-RCSM] ✓ 成功 via %s (tried=%d) account=%s chipSn=%s", api.Server, triedCount, account, chipSN)

			respJSON := map[string]interface{}{
				"code": "000000",
				"msg":  "Success",
				"data": map[string]interface{}{
					"signedDataStr":   encrypt,
					"isAllowDegraded": false,
				},
			}
			respBytes, _ := json.Marshal(respJSON)
			response := string(respBytes)

			userIP := service.GetClientIP(r)
			geoInfo := service.GetGeoInfo(userIP)
			flag := ""
			if geoInfo.Status == "success" {
				flag = service.CountryFlagEmoji(geoInfo.CountryCode)
			}

			go h.telegram.SendSignNotification(
				mainPlatform, subPlatform, chipSN, account,
				userIP, geoInfo.City, geoInfo.Country, flag,
				time.Now().Format("2006-01-02 15:04:05"),
				response,
			)
			go h.db.InsertSignLog(mainPlatform, subPlatform, chipSN, account, userIP,
				geoInfo.City, geoInfo.Country, "RCSM", "000000", "Success", response, geoInfo.Lat, geoInfo.Lon)
			go h.db.InsertFlashLog(account, "", chipSN, projectNumber, "000000", "Success", "RCSM", mainPlatform)

			h.db.MarkOTPUsed(account)
			h.db.MarkTokenUsed(clientToken)

			writeJSON(w, http.StatusOK, respJSON)
			return
		}

		errorCode := message
		if idx := strings.LastIndex(message, "："); idx != -1 {
			errorCode = message[idx+len("："):]
		}
		errorCode = strings.TrimSpace(errorCode)

		errDesc := errorCode
		if desc, ok := h.tools.errorCodes[errorCode]; ok {
			errDesc = desc
		}
		log.Printf("[Sign-RCSM] ✗ %s: [%s] %s", api.Server, errorCode, errDesc)

		// Token 过期/错误 → 继续轮询下一个区域
		if errorCode == "7005" || errorCode == "7001" || errorCode == "4004" {
			continue
		}

		// 严重签名错误 → 停止轮询，直接返回
		if errorCode == "4003" || errorCode == "4005" || errorCode == "4006" ||
			errorCode == "4007" || errorCode == "4008" || errorCode == "4009" ||
			errorCode == "4010" || errorCode == "4011" || errorCode == "4013" ||
			errorCode == "4016" || errorCode == "4020" || errorCode == "4021" ||
			errorCode == "4026" || errorCode == "4027" || errorCode == "080281" {
			log.Printf("[Sign-RCSM] 签名业务错误 [%s], 停止轮询", errorCode)

			userIP := service.GetClientIP(r)
			geoInfo := service.GetGeoInfo(userIP)
			go h.db.InsertSignLog(mainPlatform, subPlatform, chipSN, account, userIP,
				geoInfo.City, geoInfo.Country, "RCSM", errorCode, errDesc, "", geoInfo.Lat, geoInfo.Lon)
			go h.db.InsertFlashLog(account, "", chipSN, projectNumber, errorCode, errDesc, "RCSM", mainPlatform)

			writeJSON(w, http.StatusOK, map[string]interface{}{
				"code": errorCode,
				"msg":  errDesc,
				"data": nil,
			})
			return
		}
	}

	// 全部失败
	log.Printf("[Sign-RCSM] 全部失败: tried=%d skipped=%d chipSn=%s", triedCount, skipCount, chipSN)

	userIP := service.GetClientIP(r)
	geoInfo := service.GetGeoInfo(userIP)

	if triedCount == 0 {
		go h.db.InsertSignLog(mainPlatform, subPlatform, chipSN, account, userIP,
			geoInfo.City, geoInfo.Country, "RCSM", "050204", "No RCSM token available", "", geoInfo.Lat, geoInfo.Lon)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"code": "050204",
			"msg":  fmt.Sprintf("No RCSM token available (checked %d servers). Please login RCSM accounts first.", skipCount),
			"data": nil,
		})
		return
	}

	errorCode := lastMessage
	if idx := strings.LastIndex(lastMessage, "："); idx != -1 {
		errorCode = lastMessage[idx+len("："):]
	}
	errorCode = strings.TrimSpace(errorCode)

	friendlyMsg := ""
	if desc, ok := h.tools.errorCodes[errorCode]; ok {
		friendlyMsg = desc
	}
	if friendlyMsg == "" {
		friendlyMsg = fmt.Sprintf("RCSM sign failed [%s] via %s: %s", errorCode, lastServer, lastMessage)
	}

	go h.db.InsertSignLog(mainPlatform, subPlatform, chipSN, account, userIP,
		geoInfo.City, geoInfo.Country, "RCSM", errorCode, friendlyMsg, "", geoInfo.Lat, geoInfo.Lon)
	go h.db.InsertFlashLog(account, "", chipSN, projectNumber, errorCode, friendlyMsg, "RCSM", mainPlatform)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"code": errorCode,
		"msg":  friendlyMsg,
		"data": nil,
	})
}

func extractHost(rawURL string) string {
	// 简单提取 host
	u := rawURL
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimPrefix(u, "https://")
	if idx := strings.Index(u, "/"); idx != -1 {
		u = u[:idx]
	}
	return u
}
