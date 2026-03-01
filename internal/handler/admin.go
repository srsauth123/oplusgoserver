package handler

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"go-server/internal/config"
	"go-server/internal/database"
)

var startTime = time.Now()

type AdminHandler struct {
	cfg   *config.Config
	db    *database.DB
	tools *ToolsHandler
}

func NewAdminHandler(cfg *config.Config, db *database.DB) *AdminHandler {
	return &AdminHandler{cfg: cfg, db: db}
}

func (h *AdminHandler) SetToolsHandler(t *ToolsHandler) {
	h.tools = t
}

// ========== JWT ==========

func (h *AdminHandler) generateJWT(username string) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := fmt.Sprintf(`{"username":"%s","exp":%d,"iat":%d}`,
		username, time.Now().Add(72*time.Hour).Unix(), time.Now().Unix())
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(payload))

	mac := hmac.New(sha256.New, []byte(h.cfg.Admin.JWTSecret))
	mac.Write([]byte(header + "." + payloadB64))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return header + "." + payloadB64 + "." + sig, nil
}

func (h *AdminHandler) verifyJWT(tokenStr string) bool {
	tokenStr = strings.TrimPrefix(tokenStr, "Bearer ")
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return false
	}

	mac := hmac.New(sha256.New, []byte(h.cfg.Admin.JWTSecret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if expectedSig != parts[2] {
		return false
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return false
	}
	exp, ok := payload["exp"].(float64)
	if !ok || int64(exp) < time.Now().Unix() {
		return false
	}
	return true
}

// AuthMiddleware JWT 验证中间件
func (h *AdminHandler) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("authorization")
		if token == "" || !h.verifyJWT(token) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status": false, "message": "未授权，请重新登录",
			})
			return
		}
		next(w, r)
	}
}

// ========== Admin API Response ==========

func adminOK(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": true, "message": "success", "data": data,
	})
}

func adminErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": false, "message": msg,
	})
}

// ========== POST /v1/admin/login/login ==========

func (h *AdminHandler) Login(w http.ResponseWriter, r *http.Request) {
	var form struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil {
		adminErr(w, http.StatusBadRequest, "参数解析失败")
		return
	}

	if form.Username != h.cfg.Admin.Username || form.Password != h.cfg.Admin.Password {
		adminErr(w, http.StatusOK, "用户名或密码错误")
		return
	}

	token, err := h.generateJWT(form.Username)
	if err != nil {
		adminErr(w, http.StatusInternalServerError, "Token生成失败")
		return
	}

	adminOK(w, map[string]interface{}{
		"userInfo": map[string]interface{}{
			"username": form.Username,
			"nickname": "管理员",
			"userId":   "1",
			"roleId":   "1",
			"status":   true,
		},
		"token": "Bearer " + token,
	})
}

// ========== GET /v1/admin/dashboard/stats ==========

func (h *AdminHandler) DashboardStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.db.GetDashboardStats()
	if err != nil {
		log.Printf("[Admin] Dashboard stats error: %v", err)
		adminErr(w, http.StatusInternalServerError, "获取统计失败")
		return
	}
	adminOK(w, stats)
}

// ========== POST /v1/admin/active-server/get ==========

func (h *AdminHandler) GetActiveServer(w http.ResponseWriter, r *http.Request) {
	as, err := h.db.GetActivedServer()
	if err != nil {
		adminErr(w, http.StatusInternalServerError, "获取活动服务器失败")
		return
	}
	adminOK(w, as)
}

// ========== POST /v1/admin/active-server/update ==========

func (h *AdminHandler) UpdateActiveServer(w http.ResponseWriter, r *http.Request) {
	var form struct {
		Region   string `json:"region"`
		Token    string `json:"token"`
		ActiveBy string `json:"activeBy"`
		ServerID int    `json:"server_id"`
		WorkID   string `json:"workid"`
		SignURL  string `json:"sign_url"`
		SignMode string `json:"sign_mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil {
		adminErr(w, http.StatusBadRequest, "参数解析失败")
		return
	}
	if form.SignMode == "" {
		form.SignMode = "auto"
	}

	if err := h.db.UpdateActivedServer(form.Region, form.Token, form.ActiveBy, form.ServerID, form.WorkID, form.SignURL, form.SignMode); err != nil {
		adminErr(w, http.StatusInternalServerError, "更新失败: "+err.Error())
		return
	}
	adminOK(w, "更新成功")
}

// ========== POST /v1/admin/tokens/list ==========

func (h *AdminHandler) TokenList(w http.ResponseWriter, r *http.Request) {
	var form struct {
		Page     int    `json:"page"`
		PageSize int    `json:"pageSize"`
		Status   string `json:"status"`
	}
	json.NewDecoder(r.Body).Decode(&form)
	if form.Page < 1 {
		form.Page = 1
	}
	if form.PageSize < 1 {
		form.PageSize = 20
	}

	tokens, total, err := h.db.ListTokens(form.Page, form.PageSize, form.Status)
	if err != nil {
		adminErr(w, http.StatusInternalServerError, "查询失败")
		return
	}
	adminOK(w, map[string]interface{}{
		"list":  tokens,
		"total": total,
		"page":  form.Page,
	})
}

// ========== POST /v1/admin/tokens/delete ==========

func (h *AdminHandler) TokenDelete(w http.ResponseWriter, r *http.Request) {
	var form struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil {
		adminErr(w, http.StatusBadRequest, "参数解析失败")
		return
	}
	if err := h.db.DeleteToken(form.ID); err != nil {
		adminErr(w, http.StatusInternalServerError, "删除失败")
		return
	}
	adminOK(w, "删除成功")
}

// ========== POST /v1/admin/servers/list ==========

func (h *AdminHandler) ServerList(w http.ResponseWriter, r *http.Request) {
	servers, err := h.db.ListServers()
	if err != nil {
		adminErr(w, http.StatusInternalServerError, "查询失败")
		return
	}
	adminOK(w, servers)
}

// ========== POST /v1/admin/servers/create ==========

func (h *AdminHandler) ServerCreate(w http.ResponseWriter, r *http.Request) {
	var form struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Mac      string `json:"mac"`
		Region   string `json:"region"`
	}
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil {
		adminErr(w, http.StatusBadRequest, "参数解析失败")
		return
	}
	if err := h.db.CreateServer(form.Username, form.Password, form.Mac, form.Region); err != nil {
		adminErr(w, http.StatusInternalServerError, "创建失败")
		return
	}
	adminOK(w, "创建成功")
}

// ========== POST /v1/admin/servers/delete ==========

func (h *AdminHandler) ServerDelete(w http.ResponseWriter, r *http.Request) {
	var form struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil {
		adminErr(w, http.StatusBadRequest, "参数解析失败")
		return
	}
	if err := h.db.DeleteServer(form.ID); err != nil {
		adminErr(w, http.StatusInternalServerError, "删除失败")
		return
	}
	adminOK(w, "删除成功")
}

// ========== POST /v1/admin/otp/list ==========

func (h *AdminHandler) OTPList(w http.ResponseWriter, r *http.Request) {
	otps, err := h.db.ListOTPs()
	if err != nil {
		adminErr(w, http.StatusInternalServerError, "查询失败")
		return
	}
	adminOK(w, otps)
}

// ========== POST /v1/admin/otp/create ==========

func (h *AdminHandler) OTPCreate(w http.ResponseWriter, r *http.Request) {
	var form struct {
		OTP    string `json:"otp"`
		Region string `json:"region"`
	}
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil || form.OTP == "" {
		adminErr(w, http.StatusBadRequest, "参数解析失败")
		return
	}
	if err := h.db.CreateOTP(form.OTP, form.Region); err != nil {
		adminErr(w, http.StatusInternalServerError, "创建失败")
		return
	}
	adminOK(w, "创建成功")
}

// ========== POST /v1/admin/otp/toggle ==========

func (h *AdminHandler) OTPToggle(w http.ResponseWriter, r *http.Request) {
	var form struct {
		ID     int    `json:"id"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil {
		adminErr(w, http.StatusBadRequest, "参数解析失败")
		return
	}
	if form.Status != "active" && form.Status != "inactive" {
		adminErr(w, http.StatusBadRequest, "状态值无效，只能是 active 或 inactive")
		return
	}
	if err := h.db.UpdateOTPStatus(form.ID, form.Status); err != nil {
		adminErr(w, http.StatusInternalServerError, "更新失败")
		return
	}
	adminOK(w, "更新成功")
}

// ========== POST /v1/admin/otp/generate ==========

func (h *AdminHandler) OTPGenerate(w http.ResponseWriter, r *http.Request) {
	var form struct {
		Count       int    `json:"count"`
		Region      string `json:"region"`
		Prefix      string `json:"prefix"`
		TotalLength int    `json:"totalLength"`
	}
	json.NewDecoder(r.Body).Decode(&form)
	if form.Count < 1 {
		form.Count = 1
	}
	if form.Count > 50 {
		form.Count = 50
	}
	if len(form.Prefix) > 4 {
		form.Prefix = form.Prefix[:4]
	}
	if form.TotalLength < 6 || form.TotalLength > 20 {
		form.TotalLength = 10
	}
	randLen := form.TotalLength - len(form.Prefix)
	if randLen < 1 {
		randLen = 1
	}

	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	generated := make([]string, 0, form.Count)
	for i := 0; i < form.Count; i++ {
		randBytes := make([]byte, randLen)
		rand.Read(randBytes)
		randPart := make([]byte, randLen)
		for j := 0; j < randLen; j++ {
			randPart[j] = charset[int(randBytes[j])%len(charset)]
		}
		otp := form.Prefix + string(randPart)
		if err := h.db.CreateOTP(otp, form.Region); err != nil {
			adminErr(w, http.StatusInternalServerError, "生成失败")
			return
		}
		generated = append(generated, otp)
	}
	adminOK(w, map[string]interface{}{
		"count":     form.Count,
		"generated": generated,
	})
}

// ========== POST /v1/admin/otp/delete ==========

func (h *AdminHandler) OTPDelete(w http.ResponseWriter, r *http.Request) {
	var form struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil {
		adminErr(w, http.StatusBadRequest, "参数解析失败")
		return
	}
	if err := h.db.DeleteOTP(form.ID); err != nil {
		adminErr(w, http.StatusInternalServerError, "删除失败")
		return
	}
	adminOK(w, "删除成功")
}

// ========== POST /v1/admin/sign-logs/list ==========

func (h *AdminHandler) SignLogList(w http.ResponseWriter, r *http.Request) {
	var form struct {
		Page     int    `json:"page"`
		PageSize int    `json:"pageSize"`
		Keyword  string `json:"keyword"`
	}
	json.NewDecoder(r.Body).Decode(&form)
	if form.Page < 1 {
		form.Page = 1
	}
	if form.PageSize < 1 {
		form.PageSize = 20
	}
	logs, total, err := h.db.ListSignLogs(form.Page, form.PageSize, form.Keyword)
	if err != nil {
		adminErr(w, http.StatusInternalServerError, "查询失败")
		return
	}
	adminOK(w, map[string]interface{}{
		"list":  logs,
		"total": total,
		"page":  form.Page,
	})
}

// ========== POST /v1/admin/sign-forwards/list ==========

func (h *AdminHandler) SignForwardList(w http.ResponseWriter, r *http.Request) {
	forwards, err := h.db.ListSignForwards()
	if err != nil {
		adminErr(w, http.StatusInternalServerError, "查询失败")
		return
	}
	adminOK(w, forwards)
}

// ========== POST /v1/admin/sign-forwards/upsert ==========

func (h *AdminHandler) SignForwardUpsert(w http.ResponseWriter, r *http.Request) {
	var form struct {
		Region    string `json:"region"`
		TargetURL string `json:"target_url"`
		Enabled   bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil || form.Region == "" || form.TargetURL == "" {
		adminErr(w, http.StatusBadRequest, "参数解析失败")
		return
	}
	if err := h.db.UpsertSignForward(form.Region, form.TargetURL, form.Enabled); err != nil {
		adminErr(w, http.StatusInternalServerError, "保存失败")
		return
	}
	adminOK(w, "保存成功")
}

// ========== POST /v1/admin/sign-forwards/delete ==========

func (h *AdminHandler) SignForwardDelete(w http.ResponseWriter, r *http.Request) {
	var form struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil {
		adminErr(w, http.StatusBadRequest, "参数解析失败")
		return
	}
	if err := h.db.DeleteSignForward(form.ID); err != nil {
		adminErr(w, http.StatusInternalServerError, "删除失败")
		return
	}
	adminOK(w, "删除成功")
}

// ========== GET /v1/admin/geo/stats ==========

func (h *AdminHandler) GeoStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.db.GetGeoStats()
	if err != nil {
		adminErr(w, http.StatusInternalServerError, "查询失败")
		return
	}
	points, err := h.db.GetRecentSignPoints(50)
	if err != nil {
		adminErr(w, http.StatusInternalServerError, "查询失败")
		return
	}
	adminOK(w, map[string]interface{}{
		"countryStats": stats,
		"recentPoints": points,
	})
}

// ========== GET /v1/admin/login-geo/stats ==========

func (h *AdminHandler) LoginGeoStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.db.GetLoginGeoStats()
	if err != nil {
		adminErr(w, http.StatusInternalServerError, "查询失败")
		return
	}
	points, err := h.db.GetRecentLoginPoints(100)
	if err != nil {
		adminErr(w, http.StatusInternalServerError, "查询失败")
		return
	}
	adminOK(w, map[string]interface{}{
		"countryStats": stats,
		"recentPoints": points,
	})
}

// ========== GET /v1/admin/dashboard/enhanced ==========

func (h *AdminHandler) EnhancedDashboardStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.db.GetEnhancedDashboardStats()
	if err != nil {
		log.Printf("[Admin] Enhanced dashboard error: %v", err)
		adminErr(w, http.StatusInternalServerError, "查询失败")
		return
	}
	adminOK(w, stats)
}

// ========== Cert Management ==========

func (h *AdminHandler) CertList(w http.ResponseWriter, r *http.Request) {
	certs, err := h.db.ListCerts()
	if err != nil {
		adminErr(w, http.StatusInternalServerError, "查询失败")
		return
	}
	adminOK(w, certs)
}

func (h *AdminHandler) CertUpsert(w http.ResponseWriter, r *http.Request) {
	var form struct {
		Region     string `json:"region"`
		DeviceId   string `json:"device_id"`
		IV         string `json:"iv"`
		CipherInfo string `json:"cipher_info"`
	}
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil || form.Region == "" {
		adminErr(w, http.StatusBadRequest, "参数解析失败")
		return
	}
	if err := h.db.UpsertCert(form.Region, form.DeviceId, form.IV, form.CipherInfo); err != nil {
		adminErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	adminOK(w, "保存成功")
}

func (h *AdminHandler) CertDelete(w http.ResponseWriter, r *http.Request) {
	var form struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil {
		adminErr(w, http.StatusBadRequest, "参数解析失败")
		return
	}
	if err := h.db.DeleteCert(form.ID); err != nil {
		adminErr(w, http.StatusInternalServerError, "删除失败")
		return
	}
	adminOK(w, "删除成功")
}

// ========== FlashLog ==========

func (h *AdminHandler) FlashLogList(w http.ResponseWriter, r *http.Request) {
	var form struct {
		Page     int    `json:"page"`
		PageSize int    `json:"pageSize"`
		Keyword  string `json:"keyword"`
	}
	json.NewDecoder(r.Body).Decode(&form)
	if form.Page < 1 {
		form.Page = 1
	}
	if form.PageSize < 1 {
		form.PageSize = 20
	}
	logs, total, err := h.db.ListFlashLogs(form.Page, form.PageSize, form.Keyword)
	if err != nil {
		adminErr(w, http.StatusInternalServerError, "查询失败")
		return
	}
	adminOK(w, map[string]interface{}{"list": logs, "total": total})
}

// ========== NewServer Management ==========

func (h *AdminHandler) NewServerList(w http.ResponseWriter, r *http.Request) {
	servers, err := h.db.ListNewServers()
	if err != nil {
		adminErr(w, http.StatusInternalServerError, "查询失败")
		return
	}
	adminOK(w, servers)
}

func (h *AdminHandler) NewServerUpsert(w http.ResponseWriter, r *http.Request) {
	var form struct {
		Server  string  `json:"server"`
		SignURL string  `json:"signurl"`
		Region  string  `json:"region"`
		WorkID  string  `json:"workid"`
		Token   string  `json:"token"`
		Credit  float64 `json:"credit"`
		Status  string  `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil || form.Server == "" {
		adminErr(w, http.StatusBadRequest, "参数解析失败")
		return
	}
	if err := h.db.UpsertNewServer(form.Server, form.SignURL, form.Region, form.WorkID, form.Token, form.Credit, form.Status); err != nil {
		adminErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	adminOK(w, "保存成功")
}

func (h *AdminHandler) NewServerDelete(w http.ResponseWriter, r *http.Request) {
	var form struct {
		Server string `json:"server"`
	}
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil {
		adminErr(w, http.StatusBadRequest, "参数解析失败")
		return
	}
	if err := h.db.DeleteNewServer(form.Server); err != nil {
		adminErr(w, http.StatusInternalServerError, "删除失败")
		return
	}
	adminOK(w, "删除成功")
}

// ========== GET /v1/admin/client-info ==========

func (h *AdminHandler) ClientInfo(w http.ResponseWriter, r *http.Request) {
	ip := r.Header.Get("X-Real-IP")
	if ip == "" {
		ip = r.Header.Get("X-Forwarded-For")
		if idx := strings.Index(ip, ","); idx != -1 {
			ip = ip[:idx]
		}
	}
	if ip == "" {
		ip = r.RemoteAddr
		if idx := strings.LastIndex(ip, ":"); idx != -1 {
			ip = ip[:idx]
		}
	}

	// 调用 ip-api 获取地理信息
	type geoResp struct {
		Status     string  `json:"status"`
		Country    string  `json:"country"`
		RegionName string  `json:"regionName"`
		City       string  `json:"city"`
		Lat        float64 `json:"lat"`
		Lon        float64 `json:"lon"`
		Query      string  `json:"query"`
	}
	geo := geoResp{Query: ip}
	resp, err := http.Get("http://ip-api.com/json/" + ip + "?lang=zh-CN")
	if err == nil {
		defer resp.Body.Close()
		json.NewDecoder(resp.Body).Decode(&geo)
	}

	location := geo.RegionName + geo.City
	if location == "" {
		location = "-"
	}

	adminOK(w, map[string]interface{}{
		"ip":       geo.Query,
		"location": location,
		"country":  geo.Country,
		"lat":      geo.Lat,
		"lon":      geo.Lon,
	})
}

// ========== POST /v1/admin/change-password ==========

func (h *AdminHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var form struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil {
		adminErr(w, http.StatusBadRequest, "参数解析失败")
		return
	}
	if form.OldPassword != h.cfg.Admin.Password {
		adminErr(w, http.StatusOK, "旧密码错误")
		return
	}
	if len(form.NewPassword) < 6 {
		adminErr(w, http.StatusOK, "新密码至少6位")
		return
	}
	h.cfg.Admin.Password = form.NewPassword
	// 持久化到 config.yaml
	if err := h.saveConfig(); err != nil {
		log.Printf("[Admin] Save config error: %v", err)
		adminErr(w, http.StatusInternalServerError, "保存配置失败: "+err.Error())
		return
	}
	adminOK(w, "密码修改成功")
}

func (h *AdminHandler) saveConfig() error {
	data, err := os.ReadFile("config.yaml")
	if err != nil {
		return err
	}
	content := string(data)
	// 简单替换 password 行
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "password:") {
			// 检查是否在 admin 区块（前面几行有 admin:）
			for j := i - 1; j >= 0 && j >= i-3; j-- {
				if strings.TrimSpace(lines[j]) == "admin:" || strings.Contains(lines[j], "admin:") {
					lines[i] = `  password: "` + h.cfg.Admin.Password + `"`
					break
				}
			}
		}
	}
	return os.WriteFile("config.yaml", []byte(strings.Join(lines, "\n")), 0644)
}

// ========== GET /v1/admin/system/status ==========

func (h *AdminHandler) SystemStatus(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	dbStats := h.db.Stats()

	adminOK(w, map[string]interface{}{
		"uptime":        time.Since(startTime).String(),
		"uptimeSeconds": int(time.Since(startTime).Seconds()),
		"startTime":     startTime.Format("2006-01-02 15:04:05"),
		"goVersion":     runtime.Version(),
		"numGoroutine":  runtime.NumGoroutine(),
		"numCPU":        runtime.NumCPU(),
		"memAlloc":      m.Alloc / 1024 / 1024,
		"memTotal":      m.TotalAlloc / 1024 / 1024,
		"memSys":        m.Sys / 1024 / 1024,
		"numGC":         m.NumGC,
		"dbOpenConns":   dbStats.OpenConnections,
		"dbInUse":       dbStats.InUse,
		"dbIdle":        dbStats.Idle,
	})
}

// ========== POST /v1/admin/cleanup ==========

func (h *AdminHandler) Cleanup(w http.ResponseWriter, r *http.Request) {
	var form struct {
		UsedTokens bool `json:"usedTokens"`
		UsedOTPs   bool `json:"usedOTPs"`
		OldLogs    int  `json:"oldLogsDays"`
	}
	json.NewDecoder(r.Body).Decode(&form)

	results := map[string]int64{}

	if form.UsedTokens {
		res, err := h.db.CleanupUsedTokens()
		if err == nil {
			n, _ := res.RowsAffected()
			results["deletedTokens"] = n
		}
	}
	if form.UsedOTPs {
		res, err := h.db.CleanupUsedOTPs()
		if err == nil {
			n, _ := res.RowsAffected()
			results["deletedOTPs"] = n
		}
	}
	if form.OldLogs > 0 {
		res1, err1 := h.db.CleanupOldSignLogs(form.OldLogs)
		if err1 == nil {
			n, _ := res1.RowsAffected()
			results["deletedSignLogs"] = n
		}
		res2, err2 := h.db.CleanupOldFlashLogs(form.OldLogs)
		if err2 == nil {
			n, _ := res2.RowsAffected()
			results["deletedFlashLogs"] = n
		}
		res3, err3 := h.db.CleanupOldLoginLogs(form.OldLogs)
		if err3 == nil {
			n, _ := res3.RowsAffected()
			results["deletedLoginLogs"] = n
		}
	}

	adminOK(w, results)
}

// ========== POST /v1/admin/sys/users/findOne ==========

func (h *AdminHandler) UserFindOne(w http.ResponseWriter, r *http.Request) {
	adminOK(w, map[string]interface{}{
		"_id":       "1",
		"username":  h.cfg.Admin.Username,
		"nickname":  "管理员",
		"roleId":    "1",
		"status":    true,
		"createdAt": time.Now().Format(time.RFC3339),
	})
}

// ========== POST /v1/admin/sys/roles/findOne ==========

func (h *AdminHandler) RoleFindOne(w http.ResponseWriter, r *http.Request) {
	adminOK(w, map[string]interface{}{
		"_id":      "1",
		"roleName": "超级管理员",
		"roleAuth": "SUPER",
		"perms":    []string{"*"},
		"status":   true,
	})
}

// ========== RCSM Account Management ==========

func (h *AdminHandler) RCSMAccountList(w http.ResponseWriter, r *http.Request) {
	accounts, err := h.db.ListRCSMAccounts()
	if err != nil {
		adminErr(w, http.StatusInternalServerError, "查询失败")
		return
	}
	adminOK(w, accounts)
}

func (h *AdminHandler) RCSMAccountCreate(w http.ResponseWriter, r *http.Request) {
	var form struct {
		Server   string `json:"server"`
		User     string `json:"user"`
		Password string `json:"password"`
		Mac      string `json:"mac"`
	}
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil || form.Server == "" || form.User == "" {
		adminErr(w, http.StatusBadRequest, "参数解析失败")
		return
	}
	if err := h.db.CreateRCSMAccount(form.Server, form.User, form.Password, form.Mac); err != nil {
		adminErr(w, http.StatusInternalServerError, "创建失败: "+err.Error())
		return
	}
	adminOK(w, "创建成功")
}

func (h *AdminHandler) RCSMAccountDelete(w http.ResponseWriter, r *http.Request) {
	var form struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil {
		adminErr(w, http.StatusBadRequest, "参数解析失败")
		return
	}
	if err := h.db.DeleteRCSMAccount(form.ID); err != nil {
		adminErr(w, http.StatusInternalServerError, "删除失败")
		return
	}
	adminOK(w, "删除成功")
}

// ========== RCSM Token Management ==========

func (h *AdminHandler) RCSMTokenList(w http.ResponseWriter, r *http.Request) {
	tokens, err := h.db.ListRCSMTokens()
	if err != nil {
		adminErr(w, http.StatusInternalServerError, "查询失败")
		return
	}
	adminOK(w, tokens)
}

func (h *AdminHandler) RCSMTokenDelete(w http.ResponseWriter, r *http.Request) {
	var form struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil {
		adminErr(w, http.StatusBadRequest, "参数解析失败")
		return
	}
	if err := h.db.DeleteRCSMToken(form.ID); err != nil {
		adminErr(w, http.StatusInternalServerError, "删除失败")
		return
	}
	adminOK(w, "删除成功")
}

// ========== RCSM Test Login ==========
// 添加 RCSM 账号后，通过此接口测试登录拿到 token

func (h *AdminHandler) RCSMTestLogin(w http.ResponseWriter, r *http.Request) {
	var form struct {
		Server   string `json:"server"`
		User     string `json:"user"`
		Password string `json:"password"`
		Region   string `json:"region"`
		Mac      string `json:"mac"`
	}
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil || form.Server == "" {
		adminOK(w, map[string]interface{}{
			"success": false, "message": "参数解析失败: server 不能为空",
		})
		return
	}

	if h.tools == nil {
		adminOK(w, map[string]interface{}{
			"success": false, "message": "Tools handler not initialized",
		})
		return
	}

	// 区域映射（精确匹配 server name → region）
	serverUpper := strings.ToUpper(form.Server)
	regionMap := map[string]string{
		"RCSM-CN": "China", "RCSM-IN": "India", "RCSM-EU": "Europe", "RCSM-SG": "Singapore",
	}

	region := form.Region
	// 如果 region 是 server name 格式（如 RCSM-CN），转换为 config key（如 China）
	if region != "" {
		regionUpper := strings.ToUpper(region)
		if r, ok := regionMap[regionUpper]; ok {
			region = r
		} else {
			for prefix, r := range regionMap {
				if strings.HasPrefix(regionUpper, prefix) {
					region = r
					break
				}
			}
		}
	}
	if region == "" {
		// 从 server name 推断
		if r, ok := regionMap[serverUpper]; ok {
			region = r
		} else {
			for prefix, r := range regionMap {
				if strings.HasPrefix(serverUpper, prefix) {
					region = r
					break
				}
			}
		}
	}
	if region == "" {
		adminOK(w, map[string]interface{}{
			"success": false,
			"message": fmt.Sprintf("无法识别区域: %s (支持: RCSM-CN, RCSM-IN, RCSM-EU, RCSM-SG)", form.Server),
		})
		return
	}

	rcsmURL, ok := h.cfg.RCSM.URLs["login"][region]
	if !ok {
		adminOK(w, map[string]interface{}{
			"success": false,
			"message": fmt.Sprintf("区域 %s 的 RCSM 登录URL未配置，请检查 config.yaml", region),
		})
		return
	}
	secret := h.cfg.RCSM.Secrets[region]
	if secret == "" {
		adminOK(w, map[string]interface{}{
			"success": false,
			"message": fmt.Sprintf("区域 %s 的 RCSM secret未配置，请检查 config.yaml", region),
		})
		return
	}

	log.Printf("[RCSM-TestLogin] server=%s user=%s region=%s url=%s", form.Server, form.User, region, rcsmURL)

	// 执行 RCSM 登录，优先用表单传的 MAC，其次从 DB 读取账号绑定的 MAC
	testMac := form.Mac
	if testMac == "" {
		if creds, credErr := h.db.GetRCSMCredentials(form.Server); credErr == nil && creds.Mac != "" {
			testMac = creds.Mac
		}
	}
	result, token, err := h.tools.doRCSMLogin(rcsmURL, secret, form.User, form.Password, testMac)
	if err != nil {
		log.Printf("[RCSM-TestLogin] ✗ %s (%s): %v", form.Server, region, err)
		adminOK(w, map[string]interface{}{
			"success": false,
			"server":  form.Server,
			"region":  region,
			"message": fmt.Sprintf("RCSM登录失败 (%s): %s", region, err.Error()),
			"raw":     result,
		})
		return
	}

	if token != "" {
		// 保存 token 到 rcsm_token 表
		serverKey := strings.ToLower(form.Server)
		h.db.UpdateRCSMToken(serverKey, token)
		log.Printf("[RCSM-TestLogin] ✓ Token saved for %s (%s)", serverKey, region)
		tokenPreview := token
		if len(tokenPreview) > 50 {
			tokenPreview = tokenPreview[:50] + "..."
		}
		adminOK(w, map[string]interface{}{
			"success": true,
			"server":  serverKey,
			"region":  region,
			"token":   tokenPreview,
			"message": fmt.Sprintf("登录成功 (%s)，Token已保存到 %s", region, serverKey),
			"raw":     result,
		})
	} else {
		adminOK(w, map[string]interface{}{
			"success": false,
			"server":  form.Server,
			"region":  region,
			"message": fmt.Sprintf("登录失败 (%s)，RCSM未返回Token", region),
			"raw":     result,
		})
	}
}

// ========== RCSM Sign Keys Management ==========

func (h *AdminHandler) RCSMSignKeyList(w http.ResponseWriter, r *http.Request) {
	keys, err := h.db.ListRCSMSignKeys()
	if err != nil {
		adminErr(w, http.StatusInternalServerError, "查询失败")
		return
	}
	adminOK(w, keys)
}

func (h *AdminHandler) RCSMSignKeyCreate(w http.ResponseWriter, r *http.Request) {
	var form struct {
		WorkID string `json:"work_id"`
		Token  string `json:"token"`
		Region string `json:"region"`
		Note   string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil || form.WorkID == "" || form.Token == "" {
		adminErr(w, http.StatusBadRequest, "work_id 和 token 不能为空")
		return
	}
	if form.Region == "" {
		form.Region = "India"
	}
	if err := h.db.CreateRCSMSignKey(form.WorkID, form.Token, form.Region, form.Note); err != nil {
		adminErr(w, http.StatusInternalServerError, "创建失败: "+err.Error())
		return
	}
	adminOK(w, "创建成功")
}

func (h *AdminHandler) RCSMSignKeyUpdate(w http.ResponseWriter, r *http.Request) {
	var form struct {
		ID     int    `json:"id"`
		WorkID string `json:"work_id"`
		Token  string `json:"token"`
		Region string `json:"region"`
		Note   string `json:"note"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil || form.ID == 0 {
		adminErr(w, http.StatusBadRequest, "参数解析失败")
		return
	}
	if err := h.db.UpdateRCSMSignKey(form.ID, form.WorkID, form.Token, form.Region, form.Note, form.Status); err != nil {
		adminErr(w, http.StatusInternalServerError, "更新失败")
		return
	}
	adminOK(w, "更新成功")
}

func (h *AdminHandler) RCSMSignKeyToggle(w http.ResponseWriter, r *http.Request) {
	var form struct {
		ID     int    `json:"id"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil || form.ID == 0 {
		adminErr(w, http.StatusBadRequest, "参数解析失败")
		return
	}
	if err := h.db.ToggleRCSMSignKey(form.ID, form.Status); err != nil {
		adminErr(w, http.StatusInternalServerError, "更新失败")
		return
	}
	adminOK(w, "更新成功")
}

func (h *AdminHandler) RCSMSignKeyDelete(w http.ResponseWriter, r *http.Request) {
	var form struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil {
		adminErr(w, http.StatusBadRequest, "参数解析失败")
		return
	}
	if err := h.db.DeleteRCSMSignKey(form.ID); err != nil {
		adminErr(w, http.StatusInternalServerError, "删除失败")
		return
	}
	adminOK(w, "删除成功")
}
