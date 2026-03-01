package handler

import (
	"fmt"
	"net/http"
	"strings"

	"go-server/internal/config"
	"go-server/internal/database"
)

type CertHandler struct {
	cfg *config.Config
	db  *database.DB
}

func NewCertHandler(cfg *config.Config, db *database.DB) *CertHandler {
	return &CertHandler{cfg: cfg, db: db}
}

// GET /crypto/cert/upgrade
func (h *CertHandler) Upgrade(w http.ResponseWriter, r *http.Request) {
	region, err := h.db.GetActivedServerRegion()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "DB error"})
		return
	}

	certCfg, ok := h.cfg.Certs[region]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": "No cert for region: " + region})
		return
	}

	cert := strings.TrimSpace(certCfg.Cert)
	certEscaped := strings.ReplaceAll(cert, "\n", "\\n")

	response := fmt.Sprintf(`{
   "code" : 200,
   "data" : {
      "cert4Encrypt" : "%s\n",
      "cert4Sign" : "%s\n",
      "version" : %d
   },
   "traceId" : "17366715298520a04909001065918611"
}`, certEscaped, certEscaped, certCfg.Version)

	writeRaw(w, http.StatusOK, "application/json", []byte(response))
}

// GET /crypto/cert/upgradein
func (h *CertHandler) UpgradeIn(w http.ResponseWriter, r *http.Request) {
	certCfg, ok := h.cfg.Certs["India"]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": "India cert not configured"})
		return
	}

	cert := strings.TrimSpace(certCfg.Cert)
	certEscaped := strings.ReplaceAll(cert, "\n", "\\n")

	response := fmt.Sprintf(`{
   "code" : 200,
   "data" : {
      "cert4Encrypt" : "%s\n",
      "cert4Sign" : "%s\n",
      "version" : %d
   },
   "traceId" : "17454840348170a98125404491042121"
}`, certEscaped, certEscaped, certCfg.Version)

	writeRaw(w, http.StatusOK, "application/json", []byte(response))
}
