package handler

import (
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type FlashHandler struct{}

func NewFlashHandler() *FlashHandler {
	return &FlashHandler{}
}

// POST /api/flash/get_versions
func (h *FlashHandler) GetVersions(w http.ResponseWriter, r *http.Request) {
	targetURL := "https://dfs-server-gl.allawntech.com/api/flash/get_versions"

	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "Read body error"})
		return
	}
	defer r.Body.Close()

	req, err := http.NewRequest("POST", targetURL, strings.NewReader(string(rawBody)))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "Create request error"})
		return
	}

	for name, values := range r.Header {
		if strings.ToLower(name) == "host" {
			req.Header.Set("Host", "dfs-server-gl.allawntech.com")
		} else {
			for _, v := range values {
				req.Header.Add(name, v)
			}
		}
	}

	log.Printf("[Flash] → 转发到 %s | 请求体: %s", targetURL, truncStr(string(rawBody), 300))
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[Flash] ✗ 上游请求失败: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "Forward request failed: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	log.Printf("[Flash] ← 上游响应(%d): %s", resp.StatusCode, truncStr(string(respBody), 500))
	writeRaw(w, resp.StatusCode, "application/json", respBody)
}
