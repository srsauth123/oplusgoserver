package handler

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"go-server/internal/config"
	"go-server/internal/database"
)

type MiscHandler struct {
	cfg     *config.Config
	db      *database.DB
	dataDir string // 数据文件目录（flash detail、gsm 文件等）
}

func NewMiscHandler(cfg *config.Config, db *database.DB) *MiscHandler {
	// dataDir 默认为可执行文件所在目录下的 data/
	exePath, _ := os.Executable()
	dataDir := filepath.Join(filepath.Dir(exePath), "data")
	return &MiscHandler{cfg: cfg, db: db, dataDir: dataDir}
}

// ========== GET/POST /api/platform/tokenTime ==========
// 静态返回（与 PHP tokenTime.php 一致）
func (h *MiscHandler) TokenTime(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"code": "000000",
		"msg":  "Success",
		"data": 48454,
	})
}

// ========== POST /api/platform/login ==========
// V1 格式登录（account/password/mac 分别加密）— 复用 PlatformHandler.Login
// 在 main.go 中直接映射到 platformH.Login 即可

// ========== POST /api/tool/plugin/checkUpdate ==========
// 代理转发到上游 dfs-server
func (h *MiscHandler) PluginCheckUpdate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body error", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	upstream := "https://dfs-server-cn.allawntech.com/api/tool/plugin/checkUpdate"
	req, _ := http.NewRequest("POST", upstream, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("use_for", "default")
	req.Header.Set("deviceId", "OBh61nnhdCTbGNuAFqd51dvVVA3JxITB8UOMQql3EYg=")
	req.Header.Set("lang", "zh-CN")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("[checkUpdate] upstream error: %v", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// ========== POST /api/version ==========
// 版本检查：读取 data/version_config.json
func (h *MiscHandler) Version(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"status": "error", "message": "Method Not Allowed"})
		return
	}
	cfgPath := filepath.Join(h.dataDir, "version_config.json")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "error", "message": "服务器配置文件缺失"})
		return
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "error", "message": "服务器配置文件格式错误"})
		return
	}
	resp := map[string]interface{}{
		"status":         "success",
		"latest_version": cfg["latest_version"],
	}
	if fb, ok := cfg["forward_base"].(string); ok && fb != "" {
		resp["forward_base"] = fb
	}
	writeJSON(w, http.StatusOK, resp)
}

// ========== POST /api/event/trace/getBizCfgByBusinessId ==========
// 静态 JSON（与 PHP 一致）
func (h *MiscHandler) GetBizCfgByBusinessId(w http.ResponseWriter, r *http.Request) {
	cfgPath := filepath.Join(h.dataDir, "getBizCfgByBusinessId.json")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		// 返回默认静态响应
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"code": "000000",
			"msg":  "Success",
			"data": map[string]interface{}{
				"dataVersion":  nil,
				"certVersion":  1652408536857,
				"encryptScene": "dfs-ms",
				"publicKey":    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqIvzLxY/RYDhKw6NuRY97wocXE8ngTVhzqTRJHOjv8IzSqZA6cfWkbnhyDz1gCvu9g/++2ukkA2JNnFdAL6V07nPXFyh/60wujIzsVc9Enn67K/FqkQ+LP4Yn0IJ1T4xT2s4wK+tXVQawj6ro7xeHOFSS8UaCx7M6SJrGQsvmIIvQ+b5ea8a61kSZIAoiuLS2kHcrfo69Ii7hOipAPpDJkg2iAQOVihAzo/9xql+dG4FBboWJrTck15qE+V54+v7FiymmmY2f0LrF+YN9JCqCBqTpLhb2pBj6c5KHGkCm1pKhQxqkqrov7LzWs/qvQkytYteewfyDHU2wR0NwtH5AwIDAQAB",
				"tools":        []interface{}{},
			},
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// ========== POST /api/flash/v2/get_versions ==========
// Token 验证 + 读取本地 ROM JSON 文件
func (h *MiscHandler) FlashGetVersions(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Token")
	if token == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": "000002", "msg": "Error", "data": nil})
		return
	}

	// 验证 token（查 tokens 表）
	_, err := h.db.FindOriginalToken(token)
	if err != nil {
		// token 不在 tokens 表中，直接放行（兼容直接使用原始 token 的情况）
		log.Printf("[FlashGetVersions] token not in DB, allowing: %s", token[:min(len(token), 20)])
	}

	var body map[string]interface{}
	json.NewDecoder(r.Body).Decode(&body)

	marketModel, _ := body["marketModel"].(string)
	if marketModel == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": "000000", "msg": "Success", "data": nil})
		return
	}

	// 替换空格为下划线，防目录遍历
	marketModel = strings.ReplaceAll(marketModel, " ", "_")
	marketModel = strings.ReplaceAll(marketModel, "..", "")
	marketModel = strings.ReplaceAll(marketModel, "/", "")
	marketModel = strings.ReplaceAll(marketModel, "\\", "")

	if len(marketModel) > 64 {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": "000000", "msg": "Success", "data": nil})
		return
	}

	filePath := filepath.Join(h.dataDir, "flash", marketModel+".json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": "000000", "msg": "该机型无任何内容", "data": nil})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// ========== POST /api/gsm/getModelNameAll ==========
// Token 验证 + 读取本地文本文件
func (h *MiscHandler) GetModelNameAll(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Token")
	if token == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": "000002", "msg": "Error", "data": nil})
		return
	}

	// 默认 realme，我们的 platform login 返回 toolCode=REALME_TOOLSHUB
	filename := "realme.txt"

	filePath := filepath.Join(h.dataDir, "gsm", filename)
	data, err := os.ReadFile(filePath)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": "000002", "msg": "", "data": nil})
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(data)
}

// ========== GET/POST /api/gsm/getMdmArea ==========
// 静态 JSON
func (h *MiscHandler) GetMdmArea(w http.ResponseWriter, r *http.Request) {
	cfgPath := filepath.Join(h.dataDir, "gsm", "getMdmArea.json")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		// 默认返回印度区域
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"code": "000000",
			"msg":  "Success",
			"data": []map[string]interface{}{
				{"dataVersion": nil, "code": "1", "cnName": "印度", "enName": "India", "countryCode": "IN"},
			},
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// ========== POST /api/tools/cloud_validate ==========
// 静态 JSON（与 PHP 一致）
func (h *MiscHandler) CloudValidate(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"Data": map[string]interface{}{
			"message":  "0000",
			"signData": "",
			"status":   "0",
		},
		"ErrorCode": 0,
		"Message":   nil,
	})
}

// ========== POST /api/tools/get_mes_prodmodel ==========
// 静态 JSON（与 PHP 一致）
func (h *MiscHandler) GetMesProdmodel(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"Data": map[string]interface{}{
			"country_code":     "00000000",
			"country_codeau":   "00000000",
			"country_codeautt": "00000000",
			"country_codecn":   "00000000",
			"country_codefr":   "00000000",
			"prod_model":       "CPH2499SG",
			"response":         "0000",
			"status":           "0",
		},
		"ErrorCode": 0,
		"Message":   nil,
	})
}

// ========== GET /api/public/models ==========
// 列出 data/flash/ 目录下所有可用机型
func (h *MiscHandler) PublicModels(w http.ResponseWriter, r *http.Request) {
	flashDir := filepath.Join(h.dataDir, "flash")
	entries, err := os.ReadDir(flashDir)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": "000000", "data": []string{}})
		return
	}
	models := []string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		name = strings.ReplaceAll(name, "_", " ")
		models = append(models, name)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"code": "000000", "data": models})
}

// ========== GET /api/public/firmware?model=OPPO+A3+5G ==========
// 读取指定机型的固件包 JSON
func (h *MiscHandler) PublicFirmware(w http.ResponseWriter, r *http.Request) {
	model := r.URL.Query().Get("model")
	if model == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": "000001", "msg": "model is required"})
		return
	}
	// 安全处理
	model = strings.ReplaceAll(model, " ", "_")
	model = strings.ReplaceAll(model, "..", "")
	model = strings.ReplaceAll(model, "/", "")
	model = strings.ReplaceAll(model, "\\", "")
	if len(model) > 64 {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": "000001", "msg": "invalid model"})
		return
	}

	filePath := filepath.Join(h.dataDir, "flash", model+".json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": "000000", "msg": "no data", "data": nil})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
