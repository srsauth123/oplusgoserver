package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go-server/internal/config"
	"go-server/internal/crypto"
	"go-server/internal/database"
)

type ToolsHandler struct {
	cfg        *config.Config
	db         *database.DB
	errorCodes map[string]string
}

func NewToolsHandler(cfg *config.Config, db *database.DB) *ToolsHandler {
	h := &ToolsHandler{cfg: cfg, db: db, errorCodes: make(map[string]string)}
	h.loadErrorCodes()
	return h
}

func (h *ToolsHandler) loadErrorCodes() {
	// 内嵌全部 RCSM 错误码
	builtIn := map[string]string{
		"0001": "失败", "0002": "s_msg与s_msg_md5不能为空", "0003": "s_msg与s_msg_md5不匹配",
		"0004": "s_msg解密错误", "0005": "s_msg、s_msg_md5、s_msg_c不能为空", "0006": "登录不正确",
		"1001": "邮箱验证，用户邮箱不能为空！", "1002": "邮箱验证码发送失败！",
		"1003": "短信验证，用户手机不能为空！", "1004": "短信验证码发送成功！",
		"1005": "无须验证码！", "1006": "验证方式不能为空！", "1007": "账号不存在！",
		"1008": "5分钟内不重复发送", "1009": "谷歌身份验证器验证！",
		"2004": "参数mac、new_password、old_password、user_id不能为空",
		"2005": "新旧密码不能相同", "2006": "账号没维护mac地址", "2007": "账号mac地址不正确",
		"2008": "账号已禁用", "2009": "旧密码不正确", "2010": "密码修改成功",
		"2011": "账号类型没维护", "2012": "新密码强度不够", "2013": "账号已停用或者禁用",
		"2014": "账号不存在", "2015": "密码修改失败",
		"3001": "用户不存在", "3002": "验证码不能为空", "3003": "验证码不正确",
		"3004": "验证码已过期", "3005": "用户MAC地址没维护", "3006": "MAC地址不正确",
		"3007": "需要修改密码", "3008": "密码不能为空", "3009": "密码正确",
		"3010": "密码不正确", "3011": "SSO登录失败", "3012": "用户登录模式未维护",
		"3013": "谷歌身份验证码！",
		"4001": "s_msg_c解密错误", "4002": "平台密钥不存在", "4003": "账号已被锁定",
		"4004": "签名已失效", "4005": "手机与账号绑定关系不存在",
		"4006": "手机与账号绑定关系已禁用", "4007": "手机与账号绑定关系已过期",
		"4008": "手机当前软件版本在售后系统中不存在，无法刷机",
		"4009": "要刷机的软件版本在售后系统中不存在，无法刷机",
		"4010": "手机当前软件版本与刷机的软件版本对应的项目编号不一致，无法刷机",
		"4011": "您没有刷该软件版本的权限，无法刷机",
		"4012": "只有售后点账号和体验点账号才能将公开版刷为公开版",
		"4013": "当前手机中的软件版本不允许刷机",
		"4014": "只有售后账号和政企账号才能刷政企版本", "4015": "版本类型没维护",
		"4016": "HWID不匹配", "4017": "MAC不匹配", "4018": "服务器离线，请稍后尝试",
		"4019": "平台密钥不存在", "4020": "账号没申请刷机申请单", "4021": "账号刷机申请已过期",
		"4022": "账号白名单已过期", "4023": "默认可刷机量和可刷机量没有配置",
		"4024": "服务器离线，请稍后尝试", "4025": "可刷机量配置不正确",
		"4026": "7天刷机量已超过可刷机量", "4027": "7天刷机量已超过默认可刷机量",
		"4028": "回读只能是售后账号", "4029": "读写模式不能为空",
		"5001": "MAC不匹配", "6001": "非服务中心用户",
		"7001": "Token不能为空！", "7002": "参数不能为空！", "7003": "请求接口没有返回值！",
		"7004": "JSON格式错误", "7005": "Token错误！",
		"8001": "芯片ID不能为空", "8002": "平台号不能为空", "8003": "查询芯片无机型数据",
		"8004": "平台NV值不能为空", "8005": "Token不能为空", "8006": "MAC不能为空",
		"080281": "当前账号刷机次数超标，禁止刷机！！！",
		"080221": "要刷机的软件版本在售后系统中不存在，无法刷机",
		"080222": "手机当前软件版本与刷机的软件版本对应的项目编号不一致，无法刷机",
		"100282": "RCSM系统获取刷机签名失败（账号签名权限不足）",
	}
	for k, v := range builtIn {
		h.errorCodes[k] = v
	}

	// 从文件加载（覆盖内置）
	exePath, _ := os.Executable()
	filePath := filepath.Join(filepath.Dir(exePath), "data", "error_codes.json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("[Tools] error_codes.json not found, using %d built-in codes", len(h.errorCodes))
		return
	}
	if err := json.Unmarshal(data, &h.errorCodes); err != nil {
		log.Printf("[Tools] error_codes.json parse error: %v", err)
	}
	log.Printf("[Tools] Loaded %d error codes", len(h.errorCodes))
}

// ========== RCSM region config ==========

type rcsmAPI struct {
	Secret string
	URL    string
	Server string // DB rcsm_token key
}

func (h *ToolsHandler) getRCSMSignAPIs() []rcsmAPI {
	return []rcsmAPI{
		{h.cfg.RCSM.Secrets["India"], h.cfg.RCSM.URLs["sign"]["India"], "rcsm-in-3"},
		{h.cfg.RCSM.Secrets["Singapore"], h.cfg.RCSM.URLs["sign"]["Singapore"], "rcsm-sg"},
		{h.cfg.RCSM.Secrets["Singapore"], h.cfg.RCSM.URLs["sign"]["Singapore"], "rcsm-sg-2"},
		{h.cfg.RCSM.Secrets["India"], h.cfg.RCSM.URLs["sign"]["India"], "rcsm-in-2"},
		{h.cfg.RCSM.Secrets["India"], h.cfg.RCSM.URLs["sign"]["India"], "rcsm-in"},
		{h.cfg.RCSM.Secrets["Europe"], h.cfg.RCSM.URLs["sign"]["Europe"], "rcsm-eu"},
		{h.cfg.RCSM.Secrets["China"], h.cfg.RCSM.URLs["sign"]["China"], "rcsm-cn"},
	}
}

// ========== RCSM Token 自动刷新（每4小时） ==========

func (h *ToolsHandler) StartTokenRefresher() {
	// 启动时立即刷新一次
	go h.refreshAllRCSMTokens()

	ticker := time.NewTicker(4 * time.Hour)
	go func() {
		for range ticker.C {
			h.refreshAllRCSMTokens()
		}
	}()
	log.Printf("[RCSM-Refresh] Token auto-refresh started (interval: 4h)")
}

// server name → RCSM config region key
var serverToRegion = map[string]string{
	"RCSM-CN": "China", "RCSM-IN": "India", "RCSM-EU": "Europe", "RCSM-SG": "Singapore",
}

func (h *ToolsHandler) refreshAllRCSMTokens() {
	accounts, err := h.db.ListRCSMAccounts()
	if err != nil {
		log.Printf("[RCSM-Refresh] 获取账号列表失败: %v", err)
		return
	}
	if len(accounts) == 0 {
		log.Printf("[RCSM-Refresh] 无 RCSM 账号，跳过刷新")
		return
	}

	log.Printf("[RCSM-Refresh] 开始刷新 %d 个 RCSM 账号 Token...", len(accounts))
	success, failed := 0, 0

	for _, acc := range accounts {
		// 从 server name 推断区域
		serverUpper := strings.ToUpper(acc.Server)
		region := ""
		for prefix, r := range serverToRegion {
			if strings.HasPrefix(serverUpper, prefix) {
				region = r
				break
			}
		}
		if region == "" {
			log.Printf("[RCSM-Refresh] ✗ %s: 无法识别区域，跳过", acc.Server)
			failed++
			continue
		}

		rcsmURL := h.cfg.RCSM.URLs["login"][region]
		secret := h.cfg.RCSM.Secrets[region]
		if rcsmURL == "" || secret == "" {
			log.Printf("[RCSM-Refresh] ✗ %s: 区域 %s 未配置 URL/Secret，跳过", acc.Server, region)
			failed++
			continue
		}

		_, token, err := h.doRCSMLogin(rcsmURL, secret, acc.User, acc.Password, acc.Mac)
		if err != nil {
			log.Printf("[RCSM-Refresh] ✗ %s (%s/%s): %v", acc.Server, region, acc.User, err)
			failed++
			continue
		}

		serverKey := strings.ToLower(acc.Server)
		h.db.UpdateRCSMToken(serverKey, token)
		log.Printf("[RCSM-Refresh] ✓ %s (%s) Token 已更新", acc.Server, region)
		success++
	}

	log.Printf("[RCSM-Refresh] 刷新完成: 成功=%d 失败=%d 总计=%d", success, failed, len(accounts))
}

// ========== POST /api/tools/login ==========

func (h *ToolsHandler) Login(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	sMsg := r.FormValue("s_msg")
	if sMsg == "" {
		writeRaw(w, http.StatusOK, "text/html; charset=utf-8", []byte(blockedHTML))
		return
	}

	decrypted, err := crypto.DecryptRSAPrivateKey(h.cfg.RSA.PrivateKey, sMsg)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"code": "050204", "data": nil, "msg": "Decryption failed"})
		return
	}

	var dataArray map[string]interface{}
	if err := json.Unmarshal(decrypted, &dataArray); err != nil {
		writeRaw(w, http.StatusOK, "text/plain", []byte("Error decoding JSON."))
		return
	}

	userID, _ := dataArray["user_id"].(string)
	diskID, _ := dataArray["disk_id"].(string)
	ipAddr, _ := dataArray["ip"].(string)
	boardID, _ := dataArray["board_id"].(string)
	cpuID, _ := dataArray["cpu_id"].(string)

	log.Printf("[Tools-Login] 客户端请求: user=%s disk=%s ip=%s board=%s cpu=%s", userID, diskID, ipAddr, boardID, cpuID)

	// OTP 验证：优先本地，失败回退远程
	otpErr := h.db.VerifyOTP(userID)
	if otpErr != "" {
		log.Printf("[Tools-Login] OTP local failed: %s", otpErr)
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": "050204", "data": nil, "msg": otpErr})
		return
	}
	log.Printf("[Tools-Login] OTP verified: %s", userID)

	// 读取活动服务器区域配置
	activedSrv, _ := h.db.GetActivedServer()
	region := "India"
	if activedSrv != nil && activedSrv.Region != "" {
		region = activedSrv.Region
	}

	// 区域到 RCSM server name 的映射
	regionToServer := map[string]string{
		"India": "RCSM-IN", "China": "RCSM-CN", "Europe": "RCSM-EU", "Singapore": "RCSM-SG", "Eu": "RCSM-EU",
	}
	serverName := regionToServer[region]
	if serverName == "" {
		serverName = "RCSM-IN"
	}

	// 从 DB 读取凭证（rcsm_ids 表），如果没有则用默认值
	var loginUserID, loginPassword, loginMac string
	creds, err := h.db.GetRCSMCredentials(serverName)
	if err == nil && creds.User != "" {
		loginUserID = creds.User
		loginPassword = creds.Password
		loginMac = creds.Mac
	} else {
		// 默认凭证
		defaultCreds := map[string][]string{
			"India": {"IND00150", "Atul@123"}, "China": {"91001990", "realme*888K"},
			"Europe": {"19908233110", "realme*888K"}, "Singapore": {"IND00150", "Atul@123"},
			"Eu": {"19908233110", "realme*888K"},
		}
		if dc, ok := defaultCreds[region]; ok {
			loginUserID, loginPassword = dc[0], dc[1]
		} else {
			loginUserID, loginPassword = "IND00150", "Atul@123"
		}
	}
	if loginMac == "" {
		loginMac = "00-E0-4C-73-E7-47"
	}

	rcsmURL, ok := h.cfg.RCSM.URLs["login"][region]
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"code": "050204", "data": nil, "msg": "Region not configured"})
		return
	}
	secret := h.cfg.RCSM.Secrets[region]

	loginData := map[string]interface{}{
		"board_id":          boardID,
		"cpu_id":            cpuID,
		"disk_id":           diskID,
		"ip":                ipAddr,
		"login_type":        "1",
		"mac":               loginMac,
		"user_id":           loginUserID,
		"password":          loginPassword,
		"version":           "",
		"verification_code": "000000",
	}
	jsonData, _ := json.Marshal(loginData)

	encrypted, err := crypto.EncryptRSAPublicKey(h.cfg.RSA.PublicKey, jsonData)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"code": "050204", "data": nil, "msg": "Encryption failed"})
		return
	}

	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	md5Msg := crypto.MD5Hash(encrypted)

	params := map[string]string{
		"app_id":     "realme_tool",
		"timestamp":  timestamp,
		"s_msg":      encrypted,
		"s_msg_md_5": md5Msg,
	}
	sign := crypto.BuildRCSMSign("/api/tools/login", secret, params)

	formData := url.Values{
		"app_id":     {"realme_tool"},
		"timestamp":  {timestamp},
		"sign":       {sign},
		"s_msg":      {encrypted},
		"s_msg_md_5": {md5Msg},
	}

	log.Printf("[Tools-Login] → 转发到RCSM: %s region=%s user=%s", rcsmURL, region, loginUserID)
	req, _ := http.NewRequest("POST", rcsmURL, strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "MsmDownloadTool-V2.0.71-rcsm")
	req.Header.Set("Cache-Control", "no-cache")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[Tools-Login] ✗ RCSM请求失败: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"code": "050204", "data": nil, "msg": "RCSM request failed"})
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	log.Printf("[Tools-Login] ← RCSM响应(%d): %s", resp.StatusCode, truncStr(string(respBody), 500))

	// 解析 RCSM 响应
	var responseData map[string]interface{}
	if err := json.Unmarshal(respBody, &responseData); err != nil {
		log.Printf("[Tools-Login] ✗ 响应解析失败: %v", err)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"code": "050204", "data": nil,
			"msg": fmt.Sprintf("RCSM %s response parse error", region),
		})
		return
	}

	// 提取 Data.response
	data, _ := responseData["Data"].(map[string]interface{})
	response, _ := data["response"].(map[string]interface{})
	message, _ := response["message"].(string)

	if message == "0000" {
		// 登录成功 — 保存 Token
		if token, _ := response["token"].(string); token != "" {
			rcsmServer := strings.ToLower(strings.ReplaceAll(serverName, "RCSM-", "rcsm-"))
			h.db.UpdateRCSMToken(rcsmServer, token)
			log.Printf("[Tools-Login] ✓ Token saved for %s (token=%s...)", rcsmServer, truncStr(token, 30))
		}
		writeRaw(w, http.StatusOK, "application/json", respBody)
		return
	}

	// 登录失败 — 解析错误码返回友好消息
	log.Printf("[Tools-Login] ✗ RCSM登录失败: message=%s region=%s user=%s", message, region, loginUserID)

	// 提取错误码（格式可能是 "xxx：3010" 或直接 "3010"）
	errorCode := message
	if idx := strings.LastIndex(message, "："); idx != -1 {
		errorCode = message[idx+len("："):]
	}
	errorCode = strings.TrimSpace(errorCode)

	// 查找 error_codes.json 映射
	friendlyMsg := ""
	if desc, ok := h.errorCodes[errorCode]; ok {
		friendlyMsg = desc
	}

	// 常见登录错误码的额外处理
	switch errorCode {
	case "3010":
		friendlyMsg = "RCSM密码不正确 (" + region + ")"
	case "3001":
		friendlyMsg = "RCSM用户不存在: " + loginUserID + " (" + region + ")"
	case "3006":
		friendlyMsg = "MAC地址不正确 (" + region + ")"
	case "3005":
		friendlyMsg = "用户MAC地址没维护 (" + region + ")"
	case "3007":
		friendlyMsg = "需要修改密码 (" + region + ")"
	case "2008":
		friendlyMsg = "RCSM账号已禁用: " + loginUserID + " (" + region + ")"
	case "2013":
		friendlyMsg = "RCSM账号已停用或禁用: " + loginUserID + " (" + region + ")"
	case "0006":
		friendlyMsg = "RCSM登录不正确 (" + region + ")"
	}

	if friendlyMsg == "" {
		friendlyMsg = fmt.Sprintf("RCSM login failed [%s]: %s (%s)", errorCode, message, region)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"code": "050204",
		"data": nil,
		"msg":  friendlyMsg,
	})
}

// ========== POST /api/tools/sign ==========
// 支持两种输入格式:
// 1. 加密格式: form-data s_msg (RSA加密) — RCSM 客户端原始请求
// 2. 原始 JSON: {"chip_sn":"...","main_platform":"MTK",...} — 直接 JSON 请求
// 多区域轮询，从 rcsm_token 表获取各区域 token

func (h *ToolsHandler) Sign(w http.ResponseWriter, r *http.Request) {
	var dataArray map[string]interface{}
	sMsgC := "1"

	contentType := r.Header.Get("Content-Type")

	if strings.Contains(contentType, "application/json") {
		// 原始 JSON 格式
		rawBody, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"code": "050204", "data": nil, "msg": "Read body error"})
			return
		}
		defer r.Body.Close()

		if err := json.Unmarshal(rawBody, &dataArray); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"code": "050204", "data": nil, "msg": "Invalid JSON"})
			return
		}
		log.Printf("[Tools-Sign] 原始JSON请求: %s", truncStr(string(rawBody), 500))
	} else {
		// 加密格式: form-data s_msg
		r.ParseForm()
		sMsg := r.FormValue("s_msg")
		sMsgC = r.FormValue("s_msg_c")
		if sMsgC == "" {
			sMsgC = "1"
		}

		if sMsg == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"code": "050204", "data": nil, "msg": "Missing s_msg"})
			return
		}

		decrypted, err := crypto.DecryptRSAPrivateKey(h.cfg.RSA.PrivateKey, sMsg)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"code": "050204", "data": nil, "msg": "Decryption failed"})
			return
		}

		if err := json.Unmarshal(decrypted, &dataArray); err != nil {
			writeRaw(w, http.StatusOK, "text/plain", []byte("Error decoding JSON."))
			return
		}
		log.Printf("[Tools-Sign] 加密请求(解密): %s", truncStr(string(decrypted), 500))
	}

	chipSN := getStr(dataArray, "chip_sn")
	log.Printf("[Tools-Sign] chipSn=%s platform=%s", chipSN, getStr(dataArray, "main_platform"))

	// 多区域轮询签名
	apis := h.getRCSMSignAPIs()
	var lastResponse map[string]interface{}
	var lastServer string
	var lastMessage string
	triedCount := 0
	skipCount := 0

	for _, api := range apis {
		if api.URL == "" || api.Secret == "" {
			continue
		}

		// 从 DB 获取此 server 的 token
		token, err := h.db.GetRCSMToken(api.Server)
		if err != nil || token == "" {
			log.Printf("[Tools-Sign] Skip %s: no token", api.Server)
			skipCount++
			continue
		}

		triedCount++

		serverMac := "00-E0-4C-73-E7-47"
		if creds, credErr := h.db.GetRCSMCredentials(api.Server); credErr == nil && creds.Mac != "" {
			serverMac = creds.Mac
		}

		// 构造 RCSM 签名请求数据（与 rcsm-full.php generateRequestData 一致）
		signData := map[string]interface{}{
			"chip_sn":          chipSN,
			"disk_id":          "SOID8Y88",
			"ext_ip":           "0.0.0.0",
			"lock_ver":         getStr(dataArray, "lock_ver"),
			"device_type":      "1",
			"login_type":       "1",
			"mac":              serverMac,
			"main_platform":    getStr(dataArray, "main_platform"),
			"meta_ver":         "0",
			"new_project_no":   getStr(dataArray, "new_project_no"),
			"new_sw_name_sign": getStr(dataArray, "new_sw_name_sign"),
			"old_project_no":   getStr(dataArray, "old_project_no"),
			"old_sw_name_sign": getStr(dataArray, "old_sw_name_sign"),
			"random_num":       getStr(dataArray, "random_num"),
			"read_write_mode":  getStr(dataArray, "read_write_mode"),
			"sub_platform":     getStr(dataArray, "sub_platform"),
			"nv_check":         getAny(dataArray, "nv_check", false),
			"country_code":     getStr(dataArray, "country_code"),
			"nv_platForm":      getStr(dataArray, "nv_platForm"),
			"token":            token,
			"da_ver":           getStr(dataArray, "da_ver"),
			"version":          "0",
		}

		result := h.sendRCSMSignRequest(signData, api.Secret, api.URL, sMsgC)
		if result == nil {
			log.Printf("[Tools-Sign] ✗ %s: 请求失败或无响应", api.Server)
			continue
		}
		lastResponse = result
		lastServer = api.Server

		// 检查是否成功
		if data, ok := result["Data"].(map[string]interface{}); ok {
			if response, ok := data["response"].(map[string]interface{}); ok {
				encrypt, _ := response["encrypt"].(string)
				message, _ := response["message"].(string)
				lastMessage = message

				if encrypt != "" && message == "" {
					log.Printf("[Tools-Sign] ✓ 成功 via %s (tried=%d)", api.Server, triedCount)
					writeJSON(w, http.StatusOK, map[string]interface{}{
						"code": "000000",
						"msg":  "Success",
						"data": map[string]interface{}{
							"signedDataStr":   encrypt,
							"isAllowDegraded": false,
						},
					})
					return
				}

				// 解析具体错误码
				errorCode := message
				if idx := strings.LastIndex(message, "："); idx != -1 {
					errorCode = message[idx+len("："):]
				}
				errorCode = strings.TrimSpace(errorCode)

				errDesc := errorCode
				if desc, ok := h.errorCodes[errorCode]; ok {
					errDesc = desc
				}
				log.Printf("[Tools-Sign] ✗ %s: [%s] %s", api.Server, errorCode, errDesc)

				// Token 过期/错误，标记并继续轮询
				if errorCode == "7005" || errorCode == "7001" || errorCode == "4004" {
					log.Printf("[Tools-Sign] Token问题(%s), 继续轮询...", api.Server)
					continue
				}

				// 严重签名错误（非 Token 问题），直接返回不再轮询
				if errorCode == "4003" || errorCode == "4005" || errorCode == "4006" ||
					errorCode == "4007" || errorCode == "4008" || errorCode == "4009" ||
					errorCode == "4010" || errorCode == "4011" || errorCode == "4013" ||
					errorCode == "4016" || errorCode == "4020" || errorCode == "4021" ||
					errorCode == "4026" || errorCode == "4027" || errorCode == "080281" {
					log.Printf("[Tools-Sign] 签名业务错误 [%s], 停止轮询", errorCode)
					writeJSON(w, http.StatusOK, map[string]interface{}{
						"code": errorCode,
						"msg":  errDesc,
						"data": nil,
					})
					return
				}
			}
		}
	}

	// 全部失败
	log.Printf("[Tools-Sign] 全部失败: tried=%d skipped=%d chipSn=%s", triedCount, skipCount, chipSN)

	if triedCount == 0 {
		// 没有任何可用 Token
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"code": "050204",
			"msg":  fmt.Sprintf("No RCSM token available (checked %d servers). Please login RCSM accounts first.", skipCount),
			"data": nil,
		})
		return
	}

	if lastResponse != nil {
		// 从最后一次响应提取错误信息
		errorCode := lastMessage
		if idx := strings.LastIndex(lastMessage, "："); idx != -1 {
			errorCode = lastMessage[idx+len("："):]
		}
		errorCode = strings.TrimSpace(errorCode)

		friendlyMsg := ""
		if desc, ok := h.errorCodes[errorCode]; ok {
			friendlyMsg = desc
		}

		if friendlyMsg == "" {
			friendlyMsg = fmt.Sprintf("RCSM sign failed [%s] via %s: %s", errorCode, lastServer, lastMessage)
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"code": errorCode,
			"msg":  friendlyMsg,
			"data": nil,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"code": "000002",
		"msg":  fmt.Sprintf("All %d RCSM servers failed for chipSn=%s", triedCount, chipSN),
		"data": nil,
	})
}

// sendRCSMSignRequest 发送单次 RCSM 签名请求
func (h *ToolsHandler) sendRCSMSignRequest(signData map[string]interface{}, secret, rcsmURL, sMsgC string) map[string]interface{} {
	jsonData, _ := json.Marshal(signData)
	log.Printf("[RCSM-Debug] 明文数据: %s", truncStr(string(jsonData), 1000))

	encrypted, err := crypto.EncryptRSAPublicKey(h.cfg.RSA.PublicKey, jsonData)
	if err != nil {
		log.Printf("[Tools-Sign] RSA encrypt error: %v", err)
		return nil
	}

	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	md5Msg := crypto.MD5Hash(encrypted)

	params := map[string]string{
		"app_id":     "realme_tool",
		"timestamp":  timestamp,
		"s_msg":      encrypted,
		"s_msg_md_5": md5Msg,
		"s_msg_c":    sMsgC,
	}
	sign := crypto.BuildRCSMSign("/api/tools/sign", secret, params)

	formData := url.Values{
		"app_id":     {"realme_tool"},
		"timestamp":  {timestamp},
		"sign":       {sign},
		"s_msg":      {encrypted},
		"s_msg_md_5": {md5Msg},
		"s_msg_c":    {sMsgC},
	}

	host := extractHost(rcsmURL)
	log.Printf("[Tools-Sign] → %s", host)
	req, _ := http.NewRequest("POST", rcsmURL, strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "MsmDownloadTool-V2.0.71-rcsm")
	req.Header.Set("Host", host)
	req.Header.Set("Cache-Control", "no-cache")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[Tools-Sign] ✗ RCSM请求失败 %s: %v", host, err)
		return nil
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	log.Printf("[Tools-Sign] ← %s(%d): %s", host, resp.StatusCode, truncStr(string(respBody), 500))

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil
	}
	return result
}

// doRCSMLogin 执行 RCSM 登录请求，返回 (原始响应, token, error)
func (h *ToolsHandler) doRCSMLogin(rcsmURL, secret, userID, password, mac string) (map[string]interface{}, string, error) {
	if mac == "" {
		mac = "00-E0-4C-73-E7-47"
	}
	loginData := map[string]interface{}{
		"board_id":          "VQ2MV466158",
		"cpu_id":            "BFEBFBFF000306C3",
		"disk_id":           "AA20231222512G216845",
		"ip":                "0.0.0.0",
		"login_type":        "1",
		"mac":               mac,
		"user_id":           userID,
		"password":          password,
		"version":           "",
		"verification_code": "000000",
	}
	jsonData, _ := json.Marshal(loginData)

	encrypted, err := crypto.EncryptRSAPublicKey(h.cfg.RSA.PublicKey, jsonData)
	if err != nil {
		return nil, "", fmt.Errorf("RSA encrypt: %w", err)
	}

	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	md5Msg := crypto.MD5Hash(encrypted)

	params := map[string]string{
		"app_id": "realme_tool", "timestamp": timestamp,
		"s_msg": encrypted, "s_msg_md_5": md5Msg,
	}
	sign := crypto.BuildRCSMSign("/api/tools/login", secret, params)

	log.Printf("[RCSM-Login] timestamp=%s md5=%s sign=%s s_msg_len=%d", timestamp, md5Msg, sign, len(encrypted))

	formData := url.Values{
		"app_id":     {"realme_tool"},
		"timestamp":  {timestamp},
		"sign":       {sign},
		"s_msg":      {encrypted},
		"s_msg_md_5": {md5Msg},
	}

	encodedBody := formData.Encode()
	log.Printf("[RCSM-Login] → POST %s body_len=%d", rcsmURL, len(encodedBody))

	req, _ := http.NewRequest("POST", rcsmURL, strings.NewReader(encodedBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "MsmDownloadTool-V2.0.71-rcsm")
	req.Header.Set("Cache-Control", "no-cache")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	respStr := strings.TrimSpace(string(respBody))
	log.Printf("[RCSM-Login] ← 响应(%d): %s", resp.StatusCode, truncStr(respStr, 500))

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		// RCSM 返回非 JSON（可能是 HTML 错误页面）
		preview := truncStr(respStr, 200)
		return map[string]interface{}{"raw_text": preview, "http_status": resp.StatusCode},
			"", fmt.Errorf("RCSM返回非JSON响应 (HTTP %d): %s", resp.StatusCode, preview)
	}

	// 提取 token 或解析错误
	var token string
	if data, ok := result["Data"].(map[string]interface{}); ok {
		if response, ok := data["response"].(map[string]interface{}); ok {
			message, _ := response["message"].(string)
			if message == "0000" {
				token, _ = response["token"].(string)
			} else {
				// 登录失败 — 提取错误码并映射
				errorCode := message
				if idx := strings.LastIndex(message, "："); idx != -1 {
					errorCode = message[idx+len("："):]
				}
				errorCode = strings.TrimSpace(errorCode)

				errDesc := message
				if desc, ok := h.errorCodes[errorCode]; ok {
					errDesc = desc
				}
				return result, "", fmt.Errorf("[%s] %s", errorCode, errDesc)
			}
		}
	}
	if token == "" {
		return result, "", fmt.Errorf("RCSM response missing token")
	}
	return result, token, nil
}

// POST /api/sign/signrcsm
// RCSM 专用签名接口 — 使用 work_id + token 认证（不需要 OTP）
// Header: Work-Id, Token
// Body: 原始 JSON {"chip_sn":"...","main_platform":"MTK",...} 或加密格式 s_msg
// 直接调用 RCSM 官方签名 API（RSA 加密 + MD5 签名）
func (h *ToolsHandler) SignRCSM(w http.ResponseWriter, r *http.Request) {
	workID := r.Header.Get("Work-Id")
	if workID == "" {
		workID = r.Header.Get("WorkID")
	}
	clientToken := r.Header.Get("Token")

	// Step 1: 验证 Work-Id 和 Token
	if workID == "" || clientToken == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"code": "401001", "data": nil, "msg": "Missing required headers: Work-Id and Token",
		})
		return
	}

	keyRegion, err := h.db.VerifyRCSMSignKey(workID, clientToken)
	if err != nil {
		log.Printf("[SignRCSM] Auth failed: work_id=%s err=%v", workID, err)
		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"code": "403001", "data": nil, "msg": "Authentication failed: invalid or disabled Work-Id/Token",
		})
		return
	}
	log.Printf("[SignRCSM] Auth OK: work_id=%s region=%s", workID, keyRegion)

	// Step 2: 解析请求体
	var dataArray map[string]interface{}
	sMsgC := "1"
	contentType := r.Header.Get("Content-Type")

	if strings.Contains(contentType, "application/json") {
		rawBody, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"code": "400001", "data": nil, "msg": "Failed to read request body",
			})
			return
		}
		defer r.Body.Close()

		var rawJSON map[string]interface{}
		if err := json.Unmarshal(rawBody, &rawJSON); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"code": "400002", "data": nil, "msg": "Invalid JSON body",
			})
			return
		}

		// 检测是否为 AES 加密格式（businessId=FLASH_SIGN + data 含 cipher/iv）
		if dataStr, ok := rawJSON["data"].(string); ok {
			var cipherData map[string]string
			json.Unmarshal([]byte(dataStr), &cipherData)
			cipherText := cipherData["cipher"]
			iv := cipherData["iv"]
			deviceID := r.Header.Get("Deviceid")

			if cipherText != "" && iv != "" && deviceID != "" {
				// AES-256-GCM 解密
				plaintext, err := crypto.DecryptAES256GCM(cipherText, deviceID, iv)
				if err != nil {
					log.Printf("[SignRCSM] AES decrypt failed: %v", err)
					writeJSON(w, http.StatusBadRequest, map[string]interface{}{
						"code": "400006", "data": nil, "msg": "AES decryption failed",
					})
					return
				}
				if err := json.Unmarshal(plaintext, &dataArray); err != nil {
					writeJSON(w, http.StatusBadRequest, map[string]interface{}{
						"code": "400007", "data": nil, "msg": "AES decrypted data is not valid JSON",
					})
					return
				}
				log.Printf("[SignRCSM] AES加密请求(解密): %s", truncStr(string(plaintext), 500))
			} else {
				writeJSON(w, http.StatusBadRequest, map[string]interface{}{
					"code": "400003", "data": nil, "msg": "Encrypted format requires Deviceid header and cipher/iv in data",
				})
				return
			}
		} else if _, ok := rawJSON["chip_sn"]; ok {
			// 原始 JSON（snake_case）
			dataArray = rawJSON
			log.Printf("[SignRCSM] JSON请求(snake): %s", truncStr(string(rawBody), 500))
		} else if _, ok := rawJSON["chipSn"]; ok {
			// 原始 JSON（camelCase）
			dataArray = rawJSON
			log.Printf("[SignRCSM] JSON请求(camel): %s", truncStr(string(rawBody), 500))
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"code": "400005", "data": nil, "msg": "Invalid JSON format: expected chip_sn/chipSn field or encrypted data",
			})
			return
		}
	} else {
		r.ParseForm()
		sMsg := r.FormValue("s_msg")
		sMsgC = r.FormValue("s_msg_c")
		if sMsgC == "" {
			sMsgC = "1"
		}
		if sMsg == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"code": "400003", "data": nil, "msg": "Missing s_msg",
			})
			return
		}
		decrypted, err := crypto.DecryptRSAPrivateKey(h.cfg.RSA.PrivateKey, sMsg)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"code": "400004", "data": nil, "msg": "RSA decryption failed",
			})
			return
		}
		if err := json.Unmarshal(decrypted, &dataArray); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"code": "400005", "data": nil, "msg": "Decrypted data is not valid JSON",
			})
			return
		}
		log.Printf("[SignRCSM] 加密请求(解密): %s", truncStr(string(decrypted), 500))
	}

	chipSN := getStr(dataArray, "chip_sn")
	if chipSN == "" {
		chipSN = getStr(dataArray, "chipSn")
	}
	log.Printf("[SignRCSM] work_id=%s chipSn=%s platform=%s region=%s",
		workID, chipSN, getStr(dataArray, "main_platform"), keyRegion)

	// Step 3: 根据密钥区域筛选 RCSM API
	// 区域名称 → RCSM 配置 key 映射
	regionToConfigKey := map[string]string{
		"India": "India", "China": "China", "Europe": "Europe", "Eu": "Europe", "Singapore": "Singapore",
	}
	configKey := regionToConfigKey[keyRegion]
	if configKey == "" {
		configKey = "China"
	}

	signURL := h.cfg.RCSM.URLs["sign"][configKey]
	secret := h.cfg.RCSM.Secrets[configKey]
	if signURL == "" || secret == "" {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"code": "500001", "data": nil,
			"msg": fmt.Sprintf("RCSM sign config not found for region: %s", keyRegion),
		})
		return
	}

	// Step 4: 获取该区域的 RCSM token（从 rcsm_token 表）
	// 根据区域找对应的 server key
	regionToServers := map[string][]string{
		"India":     {"rcsm-in-3", "rcsm-in-2", "rcsm-in"},
		"China":     {"rcsm-cn", "rcsm-cn-2"},
		"Europe":    {"rcsm-eu"},
		"Singapore": {"rcsm-sg", "rcsm-sg-2"},
	}
	serverKeys := regionToServers[configKey]
	if len(serverKeys) == 0 {
		serverKeys = []string{"rcsm-cn"}
	}

	var rcsmToken string
	var usedServer string
	for _, sk := range serverKeys {
		t, err := h.db.GetRCSMToken(sk)
		if err == nil && t != "" {
			rcsmToken = t
			usedServer = sk
			break
		}
	}
	if rcsmToken == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"code": "500002", "data": nil,
			"msg": fmt.Sprintf("No RCSM token available for region %s. Please login RCSM accounts first.", keyRegion),
		})
		return
	}

	// Step 5: 构造 RCSM 签名请求数据（兼容 snake_case 和 camelCase 输入）
	g := func(keys ...string) string {
		for _, k := range keys {
			if v := getStr(dataArray, k); v != "" {
				return v
			}
		}
		return ""
	}
	diskID := g("disk_id", "diskId")
	if diskID == "" {
		diskID = "SOID8Y88"
	}
	mac := g("mac")
	if mac == "" {
		mac = "00-E0-4C-73-E7-47"
	}
	wo := g("workerorder", "workerOrder", "worker_order")
	if wo == "" {
		wo = "C00003639001-R251208005"
	}
	signData := map[string]interface{}{
		"chip_sn":          chipSN,
		"disk_id":          diskID,
		"ext_ip":           "0.0.0.0",
		"lock_ver":         g("lock_ver", "lockVer"),
		"device_type":      "1",
		"login_type":       "1",
		"mac":              mac,
		"main_platform":    g("main_platform", "mainPlatform"),
		"meta_ver":         "0",
		"new_project_no":   g("new_project_no", "newProjectNo"),
		"new_sw_name_sign": g("new_sw_name_sign", "newSwNameSign"),
		"old_project_no":   g("old_project_no", "oldProjectNo"),
		"old_sw_name_sign": g("old_sw_name_sign", "oldSwNameSign"),
		"random_num":       g("random_num", "randomNum"),
		"read_write_mode":  g("read_write_mode", "readWriteMode"),
		"sub_platform":     g("sub_platform", "subPlatform"),
		"nv_check":         getAny(dataArray, "nv_check", getAny(dataArray, "nvCheck", false)),
		"country_code":     g("country_code", "nvCode"),
		"nv_platForm":      g("nv_platForm", "nvPlatForm"),
		"token":            rcsmToken,
		"da_ver":           g("da_ver", "daVer"),
		"version":          "0",
		"workerorder":      wo,
		"newRemake":        g("newRemake", "new_remake"),
		"account":          g("account"),
	}

	// Step 6: RSA 加密 + MD5 签名 → 提交 RCSM 官方 API
	log.Printf("[SignRCSM] → %s via %s | region=%s", extractHost(signURL), usedServer, keyRegion)
	result := h.sendRCSMSignRequest(signData, secret, signURL, sMsgC)
	if result == nil {
		writeJSON(w, http.StatusBadGateway, map[string]interface{}{
			"code": "502001", "data": nil, "msg": "RCSM official API unreachable",
		})
		return
	}

	// Step 7: 解析 RCSM 官方响应
	if data, ok := result["Data"].(map[string]interface{}); ok {
		if response, ok := data["response"].(map[string]interface{}); ok {
			encrypt, _ := response["encrypt"].(string)
			message, _ := response["message"].(string)

			if encrypt != "" && message == "" {
				// 签名成功
				log.Printf("[SignRCSM] ✓ 签名成功 via %s | work_id=%s chipSn=%s", usedServer, workID, chipSN)
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"code": "000000",
					"msg":  "Success",
					"data": map[string]interface{}{
						"signedDataStr":   encrypt,
						"isAllowDegraded": false,
					},
				})
				return
			}

			// 签名失败 — 解析错误码
			errorCode := message
			if idx := strings.LastIndex(message, "："); idx != -1 {
				errorCode = message[idx+len("："):]
			}
			errorCode = strings.TrimSpace(errorCode)

			errDesc := errorCode
			if desc, ok := h.errorCodes[errorCode]; ok {
				errDesc = desc
			}
			log.Printf("[SignRCSM] ✗ %s: [%s] %s | work_id=%s", usedServer, errorCode, errDesc, workID)

			writeJSON(w, http.StatusOK, map[string]interface{}{
				"code": errorCode,
				"msg":  errDesc,
				"data": nil,
			})
			return
		}
	}

	// 无法解析响应
	writeJSON(w, http.StatusBadGateway, map[string]interface{}{
		"code": "502002", "data": nil, "msg": "RCSM official API returned unexpected response",
	})
}

func getStr(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getAny(m map[string]interface{}, key string, def interface{}) interface{} {
	if v, ok := m[key]; ok {
		return v
	}
	return def
}

func truncStr(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

const blockedHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Access Blocked</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body,html{height:100%;background:#f8f9fa;margin:0;font-family:sans-serif}
.c{height:100%;display:flex;justify-content:center;align-items:center}
.card{max-width:500px;padding:30px;border-radius:15px;box-shadow:0 4px 6px rgba(0,0,0,.1);background:#fff;text-align:center}
h1{font-size:2rem;color:#343a40}p{color:#6c757d;font-size:1.1rem}</style>
</head><body><div class="c"><div class="card">
<h1>Sorry, You Have Been Blocked</h1>
<p>You are unable to access this service.</p>
</div></div></body></html>`
