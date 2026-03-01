package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go-server/internal/config"
	"go-server/internal/database"
	"go-server/internal/handler"
	"go-server/internal/service"
)

// responseCapture captures status code and response body
type responseCapture struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (w *responseCapture) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *responseCapture) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip SSE stream and OPTIONS
		if strings.HasSuffix(r.URL.Path, "/logs/stream") || r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}

		// Capture request body
		var reqBody string
		if r.Body != nil && r.Method == "POST" {
			bodyBytes, _ := io.ReadAll(r.Body)
			r.Body.Close()
			reqBody = strings.TrimSpace(string(bodyBytes))
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		start := time.Now()
		rc := &responseCapture{ResponseWriter: w, status: 200}
		next.ServeHTTP(rc, r)
		duration := time.Since(start)

		ip := r.Header.Get("X-Real-IP")
		if ip == "" {
			ip = r.Header.Get("X-Forwarded-For")
			if idx := strings.Index(ip, ","); idx != -1 {
				ip = ip[:idx]
			}
		}
		if ip == "" {
			ip = r.RemoteAddr
		}

		respBody := strings.TrimSpace(rc.body.String())

		// Skip admin panel API noise
		if strings.HasPrefix(r.URL.Path, "/v1/admin/") {
			log.Printf("[%s] %s | %d | %v | %s", r.Method, r.URL.Path, rc.status, duration, ip)
			return
		}

		// Full log for business APIs
		log.Printf("[%s] %s | %d | %v | %s\n  ← REQ:  %s\n  → RESP: %s",
			r.Method, r.URL.Path, rc.status, duration, ip,
			truncate(reqBody, 500),
			truncate(respBody, 800))
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	// 优先使用命令行参数，否则在可执行文件同目录查找 config.yaml
	cfgPath := "config.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	} else {
		exePath, err := os.Executable()
		if err == nil {
			dir := filepath.Dir(exePath)
			candidate := filepath.Join(dir, "config.yaml")
			if _, err := os.Stat(candidate); err == nil {
				cfgPath = candidate
			}
		}
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	db, err := database.New(cfg.Database)
	if err != nil {
		log.Fatalf("Failed to connect database: %v", err)
	}
	defer db.Close()

	telegramSvc := service.NewTelegramService(cfg.Telegram)

	handler.InitLogBroadcaster()

	platformH := handler.NewPlatformHandler(cfg, db)
	toolsH := handler.NewToolsHandler(cfg, db)
	toolsH.StartTokenRefresher() // RCSM Token 每4小时自动刷新
	signH := handler.NewSignHandler(cfg, db, telegramSvc)
	signH.SetToolsHandler(toolsH)
	flashH := handler.NewFlashHandler()
	certH := handler.NewCertHandler(cfg, db)
	adminH := handler.NewAdminHandler(cfg, db)
	adminH.SetToolsHandler(toolsH)
	miscH := handler.NewMiscHandler(cfg, db)

	mux := http.NewServeMux()

	// API 路由 — 保持与 PHP 版本完全一致的路径
	mux.HandleFunc("/api/platform/v2/login", platformH.Login)
	mux.HandleFunc("/api/platform/login", platformH.Login)
	mux.HandleFunc("/api/platform/tokenTime", miscH.TokenTime)
	mux.HandleFunc("/api/tools/login", toolsH.Login)
	mux.HandleFunc("/api/tools/sign", toolsH.Sign)
	mux.HandleFunc("/api/tools/cloud_validate", miscH.CloudValidate)
	mux.HandleFunc("/api/tools/get_mes_prodmodel", miscH.GetMesProdmodel)
	mux.HandleFunc("/api/sign/sign", signH.Sign)
	mux.HandleFunc("/api/sign/login", signH.Login)
	mux.HandleFunc("/api/flash/get_versions", flashH.GetVersions)
	mux.HandleFunc("/api/flash/v2/get_versions", miscH.FlashGetVersions)
	mux.HandleFunc("/api/gsm/getModelNameAll", miscH.GetModelNameAll)
	mux.HandleFunc("/api/gsm/getMdmArea", miscH.GetMdmArea)
	mux.HandleFunc("/api/tool/plugin/checkUpdate", miscH.PluginCheckUpdate)
	mux.HandleFunc("/api/event/trace/getBizCfgByBusinessId", miscH.GetBizCfgByBusinessId)
	mux.HandleFunc("/api/version", miscH.Version)
	mux.HandleFunc("/api/public/models", miscH.PublicModels)
	mux.HandleFunc("/api/public/firmware", miscH.PublicFirmware)
	mux.HandleFunc("/crypto/cert/upgrade", certH.Upgrade)
	mux.HandleFunc("/crypto/cert/upgradein", certH.UpgradeIn)

	// Admin API 路由
	mux.HandleFunc("/v1/admin/login/login", adminH.Login)
	mux.HandleFunc("/v1/admin/dashboard/stats", adminH.AuthMiddleware(adminH.DashboardStats))
	mux.HandleFunc("/v1/admin/active-server/get", adminH.AuthMiddleware(adminH.GetActiveServer))
	mux.HandleFunc("/v1/admin/active-server/update", adminH.AuthMiddleware(adminH.UpdateActiveServer))
	mux.HandleFunc("/v1/admin/tokens/list", adminH.AuthMiddleware(adminH.TokenList))
	mux.HandleFunc("/v1/admin/tokens/delete", adminH.AuthMiddleware(adminH.TokenDelete))
	mux.HandleFunc("/v1/admin/servers/list", adminH.AuthMiddleware(adminH.ServerList))
	mux.HandleFunc("/v1/admin/servers/create", adminH.AuthMiddleware(adminH.ServerCreate))
	mux.HandleFunc("/v1/admin/servers/delete", adminH.AuthMiddleware(adminH.ServerDelete))
	mux.HandleFunc("/v1/admin/otp/list", adminH.AuthMiddleware(adminH.OTPList))
	mux.HandleFunc("/v1/admin/otp/create", adminH.AuthMiddleware(adminH.OTPCreate))
	mux.HandleFunc("/v1/admin/otp/toggle", adminH.AuthMiddleware(adminH.OTPToggle))
	mux.HandleFunc("/v1/admin/otp/generate", adminH.AuthMiddleware(adminH.OTPGenerate))
	mux.HandleFunc("/v1/admin/otp/delete", adminH.AuthMiddleware(adminH.OTPDelete))
	mux.HandleFunc("/v1/admin/sign-logs/list", adminH.AuthMiddleware(adminH.SignLogList))
	mux.HandleFunc("/v1/admin/sign-forwards/list", adminH.AuthMiddleware(adminH.SignForwardList))
	mux.HandleFunc("/v1/admin/sign-forwards/upsert", adminH.AuthMiddleware(adminH.SignForwardUpsert))
	mux.HandleFunc("/v1/admin/sign-forwards/delete", adminH.AuthMiddleware(adminH.SignForwardDelete))
	mux.HandleFunc("/v1/admin/geo/stats", adminH.AuthMiddleware(adminH.GeoStats))
	mux.HandleFunc("/v1/admin/dashboard/enhanced", adminH.AuthMiddleware(adminH.EnhancedDashboardStats))
	mux.HandleFunc("/v1/admin/login-geo/stats", adminH.AuthMiddleware(adminH.LoginGeoStats))
	mux.HandleFunc("/v1/admin/certs/list", adminH.AuthMiddleware(adminH.CertList))
	mux.HandleFunc("/v1/admin/certs/upsert", adminH.AuthMiddleware(adminH.CertUpsert))
	mux.HandleFunc("/v1/admin/certs/delete", adminH.AuthMiddleware(adminH.CertDelete))
	mux.HandleFunc("/v1/admin/flash-logs/list", adminH.AuthMiddleware(adminH.FlashLogList))
	mux.HandleFunc("/v1/admin/new-servers/list", adminH.AuthMiddleware(adminH.NewServerList))
	mux.HandleFunc("/v1/admin/new-servers/upsert", adminH.AuthMiddleware(adminH.NewServerUpsert))
	mux.HandleFunc("/v1/admin/new-servers/delete", adminH.AuthMiddleware(adminH.NewServerDelete))
	mux.HandleFunc("/v1/admin/client-info", adminH.AuthMiddleware(adminH.ClientInfo))
	mux.HandleFunc("/v1/admin/change-password", adminH.AuthMiddleware(adminH.ChangePassword))
	mux.HandleFunc("/v1/admin/system/status", adminH.AuthMiddleware(adminH.SystemStatus))
	mux.HandleFunc("/v1/admin/cleanup", adminH.AuthMiddleware(adminH.Cleanup))
	mux.HandleFunc("/v1/admin/logs/stream", adminH.LogStreamAuth(adminH.LogStream))
	mux.HandleFunc("/v1/admin/sys/users/findOne", adminH.AuthMiddleware(adminH.UserFindOne))
	mux.HandleFunc("/v1/admin/sys/roles/findOne", adminH.AuthMiddleware(adminH.RoleFindOne))
	mux.HandleFunc("/v1/admin/rcsm/accounts/list", adminH.AuthMiddleware(adminH.RCSMAccountList))
	mux.HandleFunc("/v1/admin/rcsm/accounts/create", adminH.AuthMiddleware(adminH.RCSMAccountCreate))
	mux.HandleFunc("/v1/admin/rcsm/accounts/delete", adminH.AuthMiddleware(adminH.RCSMAccountDelete))
	mux.HandleFunc("/v1/admin/rcsm/tokens/list", adminH.AuthMiddleware(adminH.RCSMTokenList))
	mux.HandleFunc("/v1/admin/rcsm/tokens/delete", adminH.AuthMiddleware(adminH.RCSMTokenDelete))
	mux.HandleFunc("/v1/admin/rcsm/test-login", adminH.AuthMiddleware(adminH.RCSMTestLogin))
	mux.HandleFunc("/v1/admin/rcsm/sign-keys/list", adminH.AuthMiddleware(adminH.RCSMSignKeyList))
	mux.HandleFunc("/v1/admin/rcsm/sign-keys/create", adminH.AuthMiddleware(adminH.RCSMSignKeyCreate))
	mux.HandleFunc("/v1/admin/rcsm/sign-keys/update", adminH.AuthMiddleware(adminH.RCSMSignKeyUpdate))
	mux.HandleFunc("/v1/admin/rcsm/sign-keys/toggle", adminH.AuthMiddleware(adminH.RCSMSignKeyToggle))
	mux.HandleFunc("/v1/admin/rcsm/sign-keys/delete", adminH.AuthMiddleware(adminH.RCSMSignKeyDelete))

	// RCSM 专用签名接口（work_id + token 认证，不需要 OTP，直接调 RCSM 官方 API）
	mux.HandleFunc("/api/sign/signrcsm", toolsH.SignRCSM)

	// 日志 + CORS 中间件包裹
	corsHandler := corsMiddleware(loggingMiddleware(mux))

	// 前端管理面板：在最外层拦截 /admin 请求
	exePath, _ := os.Executable()
	distDir := filepath.Join(filepath.Dir(exePath), "admin")
	var finalHandler http.Handler = corsHandler
	if _, err := os.Stat(distDir); err == nil {
		log.Printf("Admin panel: serving /admin/ from %s", distDir)
		finalHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 只处理 /admin 开头且不是 /v1/ 的请求
			if (r.URL.Path == "/admin" || strings.HasPrefix(r.URL.Path, "/admin/")) && !strings.HasPrefix(r.URL.Path, "/v1/") {
				// 去掉 /admin 前缀得到文件路径
				filePath := strings.TrimPrefix(r.URL.Path, "/admin")
				if filePath == "" || filePath == "/" {
					filePath = "/index.html"
				}
				fullPath := filepath.Join(distDir, filepath.Clean(filePath))
				// 文件不存在则返回 index.html（SPA fallback）
				if _, err := os.Stat(fullPath); os.IsNotExist(err) {
					http.ServeFile(w, r, filepath.Join(distDir, "index.html"))
					return
				}
				http.ServeFile(w, r, fullPath)
				return
			}
			corsHandler.ServeHTTP(w, r)
		})
	} else {
		log.Printf("Warning: admin dir not found at %s", distDir)
	}

	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	log.Printf("Server starting on %s", addr)
	if err := http.ListenAndServe(addr, finalHandler); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
