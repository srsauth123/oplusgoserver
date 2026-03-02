package database

import (
	"database/sql"
	"fmt"
)

// ========== Dashboard ==========

type DashboardStats struct {
	TotalTokens  int    `json:"totalTokens"`
	UsedTokens   int    `json:"usedTokens"`
	UnusedTokens int    `json:"unusedTokens"`
	TotalServers int    `json:"totalServers"`
	TotalOTPs    int    `json:"totalOTPs"`
	TodaySigns   int    `json:"todaySigns"`
	ActiveRegion string `json:"activeRegion"`
	ActiveBy     string `json:"activeBy"`
}

func (db *DB) GetDashboardStats() (*DashboardStats, error) {
	var stats DashboardStats

	db.conn.QueryRow("SELECT COUNT(*) FROM tokens").Scan(&stats.TotalTokens)
	db.conn.QueryRow("SELECT COUNT(*) FROM tokens WHERE status='used'").Scan(&stats.UsedTokens)
	db.conn.QueryRow("SELECT COUNT(*) FROM tokens WHERE status='unused'").Scan(&stats.UnusedTokens)
	db.conn.QueryRow("SELECT COUNT(*) FROM servers").Scan(&stats.TotalServers)
	db.conn.QueryRow("SELECT COUNT(*) FROM cotp").Scan(&stats.TotalOTPs)
	db.conn.QueryRow("SELECT COUNT(*) FROM sign_logs WHERE DATE(created_at)=CURDATE()").Scan(&stats.TodaySigns)
	db.conn.QueryRow("SELECT region FROM actived_server WHERE id=1").Scan(&stats.ActiveRegion)
	db.conn.QueryRow("SELECT activeBy FROM actived_server WHERE id=1").Scan(&stats.ActiveBy)

	return &stats, nil
}

// ========== Active Server ==========

func (db *DB) UpdateActivedServer(region, token, activeBy string, serverID int, workid, signURL, signMode string) error {
	_, err := db.conn.Exec(
		"UPDATE actived_server SET region=?, token=?, activeBy=?, server_id=?, workid=?, sign_url=?, sign_mode=? WHERE id=1",
		region, token, activeBy, serverID, workid, signURL, signMode,
	)
	return err
}

// ========== Tokens ==========

type TokenRecord struct {
	ID             int    `json:"id"`
	GeneratedToken string `json:"generated_token"`
	OriginalToken  string `json:"original_token"`
	Status         string `json:"status"`
}

func (db *DB) ListTokens(page, pageSize int, status string) ([]TokenRecord, int, error) {
	var total int
	countSQL := "SELECT COUNT(*) FROM tokens"
	listSQL := "SELECT id, generated_token, original_token, status FROM tokens"

	if status != "" {
		countSQL += fmt.Sprintf(" WHERE status='%s'", status)
		listSQL += fmt.Sprintf(" WHERE status='%s'", status)
	}

	db.conn.QueryRow(countSQL).Scan(&total)

	listSQL += fmt.Sprintf(" ORDER BY id DESC LIMIT %d OFFSET %d", pageSize, (page-1)*pageSize)
	rows, err := db.conn.Query(listSQL)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var tokens []TokenRecord
	for rows.Next() {
		var t TokenRecord
		rows.Scan(&t.ID, &t.GeneratedToken, &t.OriginalToken, &t.Status)
		tokens = append(tokens, t)
	}
	if tokens == nil {
		tokens = []TokenRecord{}
	}
	return tokens, total, nil
}

func (db *DB) DeleteToken(id int) error {
	_, err := db.conn.Exec("DELETE FROM tokens WHERE id=?", id)
	return err
}

// ========== Servers ==========

type ServerRecord struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Mac      string `json:"mac"`
	Region   string `json:"region"`
}

func (db *DB) ListServers() ([]ServerRecord, error) {
	rows, err := db.conn.Query("SELECT id, username, password, mac, region FROM servers ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []ServerRecord
	for rows.Next() {
		var s ServerRecord
		rows.Scan(&s.ID, &s.Username, &s.Password, &s.Mac, &s.Region)
		servers = append(servers, s)
	}
	if servers == nil {
		servers = []ServerRecord{}
	}
	return servers, nil
}

func (db *DB) CreateServer(username, password, mac, region string) error {
	_, err := db.conn.Exec(
		"INSERT INTO servers (username, password, mac, region) VALUES (?, ?, ?, ?)",
		username, password, mac, region,
	)
	return err
}

func (db *DB) DeleteServer(id int) error {
	_, err := db.conn.Exec("DELETE FROM servers WHERE id=?", id)
	return err
}

// ========== OTP ==========

type OTPRecord struct {
	ID        int    `json:"id"`
	OTP       string `json:"otp"`
	Status    string `json:"status"`
	Region    string `json:"region"`
	CreatedAt string `json:"created_at"`
}

func (db *DB) ListOTPs() ([]OTPRecord, error) {
	rows, err := db.conn.Query("SELECT id, otp, IFNULL(status,'active'), IFNULL(region,'Eu'), IFNULL(created_at,'') FROM cotp ORDER BY id DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var otps []OTPRecord
	for rows.Next() {
		var o OTPRecord
		rows.Scan(&o.ID, &o.OTP, &o.Status, &o.Region, &o.CreatedAt)
		otps = append(otps, o)
	}
	if otps == nil {
		otps = []OTPRecord{}
	}
	return otps, nil
}

// VerifyOTP 返回空字符串表示验证通过，否则返回具体错误原因
func (db *DB) VerifyOTP(otp string) string {
	var status string
	err := db.conn.QueryRow("SELECT IFNULL(status,'active') FROM cotp WHERE otp=? OR otp LIKE CONCAT(?,'%') LIMIT 1", otp, otp).Scan(&status)
	if err != nil {
		return "OTP code not found"
	}
	switch status {
	case "active":
		return ""
	case "used":
		return "OTP code already used"
	case "inactive":
		return "OTP code has been disabled"
	default:
		return "OTP code status invalid: " + status
	}
}

func (db *DB) CreateOTP(otp, region string) error {
	if region == "" {
		region = "Eu"
	}
	_, err := db.conn.Exec("INSERT INTO cotp (otp, status, region) VALUES (?, 'active', ?)", otp, region)
	return err
}

func (db *DB) UpdateOTPStatus(id int, status string) error {
	_, err := db.conn.Exec("UPDATE cotp SET status=? WHERE id=?", status, id)
	return err
}

func (db *DB) DeleteOTP(id int) error {
	_, err := db.conn.Exec("DELETE FROM cotp WHERE id=?", id)
	return err
}

func (db *DB) MarkOTPUsed(otp string) {
	db.conn.Exec("UPDATE cotp SET status='used' WHERE otp=? OR otp LIKE CONCAT(?,'%')", otp, otp)
}

// ========== Sign Logs ==========

type SignLog struct {
	ID           int    `json:"id"`
	Platform     string `json:"platform"`
	Chipset      string `json:"chipset"`
	SerialNumber string `json:"serial_number"`
	Account      string `json:"account"`
	ClientIP     string `json:"client_ip"`
	City         string `json:"city"`
	Country      string `json:"country"`
	Region       string `json:"region"`
	ResultCode   string `json:"result_code"`
	ResultMsg    string `json:"result_msg"`
	Response     string `json:"response"`
	CreatedAt    string `json:"created_at"`
}

func (db *DB) InsertSignLog(platform, chipset, serialNumber, account, clientIP, city, country, region, resultCode, resultMsg, response string, lat, lon float64) error {
	_, err := db.conn.Exec(
		`INSERT INTO sign_logs (platform, chipset, serial_number, account, client_ip, city, country, region, result_code, result_msg, response, lat, lon)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		platform, chipset, serialNumber, account, clientIP, city, country, region, resultCode, resultMsg, response, lat, lon,
	)
	return err
}

func (db *DB) ListSignLogs(page, pageSize int, keyword string) ([]SignLog, int, error) {
	var total int
	countSQL := "SELECT COUNT(*) FROM sign_logs"
	listSQL := "SELECT id, platform, chipset, serial_number, account, client_ip, city, country, region, result_code, result_msg, IFNULL(response,''), created_at FROM sign_logs"

	where := ""
	if keyword != "" {
		where = fmt.Sprintf(" WHERE serial_number LIKE '%%%s%%' OR account LIKE '%%%s%%' OR platform LIKE '%%%s%%' OR client_ip LIKE '%%%s%%'", keyword, keyword, keyword, keyword)
	}

	db.conn.QueryRow(countSQL + where).Scan(&total)

	listSQL += where + fmt.Sprintf(" ORDER BY id DESC LIMIT %d OFFSET %d", pageSize, (page-1)*pageSize)
	rows, err := db.conn.Query(listSQL)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []SignLog
	for rows.Next() {
		var l SignLog
		rows.Scan(&l.ID, &l.Platform, &l.Chipset, &l.SerialNumber, &l.Account, &l.ClientIP, &l.City, &l.Country, &l.Region, &l.ResultCode, &l.ResultMsg, &l.Response, &l.CreatedAt)
		logs = append(logs, l)
	}
	if logs == nil {
		logs = []SignLog{}
	}
	return logs, total, nil
}

// ========== Sign Forwards ==========

type SignForward struct {
	ID        int    `json:"id"`
	Region    string `json:"region"`
	TargetURL string `json:"target_url"`
	Enabled   bool   `json:"enabled"`
}

func (db *DB) ListSignForwards() ([]SignForward, error) {
	rows, err := db.conn.Query("SELECT id, region, target_url, enabled FROM sign_forwards ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var forwards []SignForward
	for rows.Next() {
		var f SignForward
		rows.Scan(&f.ID, &f.Region, &f.TargetURL, &f.Enabled)
		forwards = append(forwards, f)
	}
	if forwards == nil {
		forwards = []SignForward{}
	}
	return forwards, nil
}

func (db *DB) UpsertSignForward(region, targetURL string, enabled bool) error {
	_, err := db.conn.Exec(
		`INSERT INTO sign_forwards (region, target_url, enabled) VALUES (?, ?, ?)
		 ON DUPLICATE KEY UPDATE target_url=VALUES(target_url), enabled=VALUES(enabled)`,
		region, targetURL, enabled,
	)
	return err
}

func (db *DB) DeleteSignForward(id int) error {
	_, err := db.conn.Exec("DELETE FROM sign_forwards WHERE id=?", id)
	return err
}

// ========== Sign Forward URL Lookup ==========

func (db *DB) GetSignForwardURL(region string) (string, error) {
	var url string
	err := db.conn.QueryRow(
		"SELECT target_url FROM sign_forwards WHERE region=? AND enabled=1 LIMIT 1", region,
	).Scan(&url)
	return url, err
}

// ========== new_server Table ==========

type NewServerConfig struct {
	Server  string  `json:"server"`
	SignURL string  `json:"signurl"`
	Region  string  `json:"region"`
	WorkID  string  `json:"workid"`
	Token   string  `json:"token"`
	Credit  float64 `json:"credit"`
	Status  string  `json:"status"`
}

func (db *DB) GetNewServerByType(serverType string) (*NewServerConfig, error) {
	var s NewServerConfig
	err := db.conn.QueryRow(
		"SELECT server, signurl, region, workid, token, credit, IFNULL(status,'Online') FROM new_server WHERE server=?",
		serverType,
	).Scan(&s.Server, &s.SignURL, &s.Region, &s.WorkID, &s.Token, &s.Credit, &s.Status)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// ========== cert Table ==========

type CertRecord struct {
	Region     string `json:"region"`
	DeviceId   string `json:"device_id"`
	IV         string `json:"iv"`
	CipherInfo string `json:"cipher_info"`
}

func (db *DB) GetCertByRegion(region string) (*CertRecord, error) {
	var c CertRecord
	err := db.conn.QueryRow(
		"SELECT Region, DeviceId, IV, CipherInfo FROM cert WHERE Region=?", region,
	).Scan(&c.Region, &c.DeviceId, &c.IV, &c.CipherInfo)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// ========== User / Card Validation (PHP equivalent) ==========

type UserRecord struct {
	Username string
	Password string
	Stats    string
	Balance  float64
}

func (db *DB) ValidateUser(account string) (*UserRecord, error) {
	var u UserRecord
	err := db.conn.QueryRow(
		"SELECT username, IFNULL(password,''), IFNULL(stats,''), IFNULL(balance,0) FROM users WHERE username=?",
		account,
	).Scan(&u.Username, &u.Password, &u.Stats, &u.Balance)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

type CardRecord struct {
	Username string
	Credit   int
	Type     string
	Status   string
}

func (db *DB) ValidateCard(account string) (*CardRecord, error) {
	var c CardRecord
	err := db.conn.QueryRow(
		"SELECT Username, IFNULL(Credit,0), IFNULL(Type,'Realme'), IFNULL(Status,'') FROM Cardtable WHERE Username=?",
		account,
	).Scan(&c.Username, &c.Credit, &c.Type, &c.Status)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (db *DB) DeductUserBalance(account string, amount float64) error {
	_, err := db.conn.Exec("UPDATE users SET balance = balance - ? WHERE username = ?", amount, account)
	return err
}

func (db *DB) DeductCardCredit(account string, amount float64) error {
	_, err := db.conn.Exec("UPDATE Cardtable SET Credit = Credit - ? WHERE Username = ?", amount, account)
	return err
}

// ========== flashlog Table ==========

func (db *DB) InsertFlashLog(username, ticket, sn, projectNo, code, msg, serverType, platform string) {
	db.conn.Exec(
		"INSERT INTO flashlog (username, ticket, sn, projectNo, code, msg, type, time, platform) VALUES (?,?,?,?,?,?,?,NOW(),?)",
		username, ticket, sn, projectNo, code, msg, serverType, platform,
	)
}

// ========== Cert CRUD ==========

type CertItem struct {
	ID         int    `json:"id"`
	Region     string `json:"region"`
	DeviceId   string `json:"device_id"`
	IV         string `json:"iv"`
	CipherInfo string `json:"cipher_info"`
}

func (db *DB) ListCerts() ([]CertItem, error) {
	rows, err := db.conn.Query("SELECT id, Region, DeviceId, IV, CipherInfo FROM cert ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var certs []CertItem
	for rows.Next() {
		var c CertItem
		rows.Scan(&c.ID, &c.Region, &c.DeviceId, &c.IV, &c.CipherInfo)
		certs = append(certs, c)
	}
	if certs == nil {
		certs = []CertItem{}
	}
	return certs, nil
}

func (db *DB) UpsertCert(region, deviceId, iv, cipherInfo string) error {
	_, err := db.conn.Exec(
		`INSERT INTO cert (Region, DeviceId, IV, CipherInfo) VALUES (?, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE DeviceId=VALUES(DeviceId), IV=VALUES(IV), CipherInfo=VALUES(CipherInfo)`,
		region, deviceId, iv, cipherInfo,
	)
	return err
}

func (db *DB) DeleteCert(id int) error {
	_, err := db.conn.Exec("DELETE FROM cert WHERE id=?", id)
	return err
}

// ========== FlashLog List ==========

type FlashLogRecord struct {
	ID        int    `json:"id"`
	Username  string `json:"username"`
	Ticket    string `json:"ticket"`
	SN        string `json:"sn"`
	ProjectNo string `json:"projectNo"`
	Code      string `json:"code"`
	Msg       string `json:"msg"`
	Type      string `json:"type"`
	Time      string `json:"time"`
	Platform  string `json:"platform"`
}

func (db *DB) ListFlashLogs(page, pageSize int, keyword string) ([]FlashLogRecord, int, error) {
	var total int
	countSQL := "SELECT COUNT(*) FROM flashlog"
	listSQL := "SELECT id, IFNULL(username,''), IFNULL(ticket,''), IFNULL(sn,''), IFNULL(projectNo,''), IFNULL(code,''), IFNULL(msg,''), IFNULL(type,''), IFNULL(time,''), IFNULL(platform,'') FROM flashlog"

	where := ""
	if keyword != "" {
		where = fmt.Sprintf(" WHERE sn LIKE '%%%s%%' OR username LIKE '%%%s%%' OR platform LIKE '%%%s%%' OR code LIKE '%%%s%%'", keyword, keyword, keyword, keyword)
	}
	db.conn.QueryRow(countSQL + where).Scan(&total)

	listSQL += where + fmt.Sprintf(" ORDER BY id DESC LIMIT %d OFFSET %d", pageSize, (page-1)*pageSize)
	rows, err := db.conn.Query(listSQL)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []FlashLogRecord
	for rows.Next() {
		var l FlashLogRecord
		rows.Scan(&l.ID, &l.Username, &l.Ticket, &l.SN, &l.ProjectNo, &l.Code, &l.Msg, &l.Type, &l.Time, &l.Platform)
		logs = append(logs, l)
	}
	if logs == nil {
		logs = []FlashLogRecord{}
	}
	return logs, total, nil
}

// ========== NewServer CRUD ==========

func (db *DB) ListNewServers() ([]NewServerConfig, error) {
	rows, err := db.conn.Query("SELECT server, IFNULL(signurl,''), IFNULL(region,''), IFNULL(workid,''), IFNULL(token,''), IFNULL(credit,0), IFNULL(status,'Online') FROM new_server ORDER BY server")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var servers []NewServerConfig
	for rows.Next() {
		var s NewServerConfig
		rows.Scan(&s.Server, &s.SignURL, &s.Region, &s.WorkID, &s.Token, &s.Credit, &s.Status)
		servers = append(servers, s)
	}
	if servers == nil {
		servers = []NewServerConfig{}
	}
	return servers, nil
}

func (db *DB) UpsertNewServer(server, signurl, region, workid, token string, credit float64, status string) error {
	_, err := db.conn.Exec(
		`INSERT INTO new_server (server, signurl, region, workid, token, credit, status) VALUES (?,?,?,?,?,?,?)
		 ON DUPLICATE KEY UPDATE signurl=VALUES(signurl), region=VALUES(region), workid=VALUES(workid), token=VALUES(token), credit=VALUES(credit), status=VALUES(status)`,
		server, signurl, region, workid, token, credit, status,
	)
	return err
}

func (db *DB) DeleteNewServer(server string) error {
	_, err := db.conn.Exec("DELETE FROM new_server WHERE server=?", server)
	return err
}

// ========== Enhanced Dashboard Stats ==========

type EnhancedDashboardStats struct {
	TotalTokens  int          `json:"totalTokens"`
	UsedTokens   int          `json:"usedTokens"`
	UnusedTokens int          `json:"unusedTokens"`
	TotalServers int          `json:"totalServers"`
	TotalOTPs    int          `json:"totalOTPs"`
	ActiveOTPs   int          `json:"activeOTPs"`
	UsedOTPs     int          `json:"usedOTPs"`
	TodaySigns   int          `json:"todaySigns"`
	TodaySuccess int          `json:"todaySuccess"`
	TodayFail    int          `json:"todayFail"`
	SuccessRate  float64      `json:"successRate"`
	ActiveRegion string       `json:"activeRegion"`
	ActiveBy     string       `json:"activeBy"`
	RegionStats  []RegionStat `json:"regionStats"`
	WeeklyTrend  []DayStat    `json:"weeklyTrend"`
}

type RegionStat struct {
	Region string `json:"region"`
	Count  int    `json:"count"`
}

type DayStat struct {
	Date    string `json:"date"`
	Success int    `json:"success"`
	Fail    int    `json:"fail"`
}

func (db *DB) GetEnhancedDashboardStats() (*EnhancedDashboardStats, error) {
	var s EnhancedDashboardStats
	db.conn.QueryRow("SELECT COUNT(*) FROM tokens").Scan(&s.TotalTokens)
	db.conn.QueryRow("SELECT COUNT(*) FROM tokens WHERE status='used'").Scan(&s.UsedTokens)
	db.conn.QueryRow("SELECT COUNT(*) FROM tokens WHERE status='unused'").Scan(&s.UnusedTokens)
	db.conn.QueryRow("SELECT COUNT(*) FROM servers").Scan(&s.TotalServers)
	db.conn.QueryRow("SELECT COUNT(*) FROM cotp").Scan(&s.TotalOTPs)
	db.conn.QueryRow("SELECT COUNT(*) FROM cotp WHERE status='active'").Scan(&s.ActiveOTPs)
	db.conn.QueryRow("SELECT COUNT(*) FROM cotp WHERE status='used'").Scan(&s.UsedOTPs)
	db.conn.QueryRow("SELECT COUNT(*) FROM sign_logs WHERE DATE(created_at)=CURDATE()").Scan(&s.TodaySigns)
	db.conn.QueryRow("SELECT COUNT(*) FROM sign_logs WHERE DATE(created_at)=CURDATE() AND result_code='000000'").Scan(&s.TodaySuccess)
	db.conn.QueryRow("SELECT COUNT(*) FROM sign_logs WHERE DATE(created_at)=CURDATE() AND result_code!='000000'").Scan(&s.TodayFail)
	db.conn.QueryRow("SELECT region FROM actived_server WHERE id=1").Scan(&s.ActiveRegion)
	db.conn.QueryRow("SELECT activeBy FROM actived_server WHERE id=1").Scan(&s.ActiveBy)

	if s.TodaySigns > 0 {
		s.SuccessRate = float64(s.TodaySuccess) / float64(s.TodaySigns) * 100
	}

	// 区域饼图
	regionRows, err := db.conn.Query("SELECT IFNULL(region,'Unknown'), COUNT(*) FROM sign_logs GROUP BY region ORDER BY COUNT(*) DESC")
	if err == nil {
		defer regionRows.Close()
		for regionRows.Next() {
			var rs RegionStat
			regionRows.Scan(&rs.Region, &rs.Count)
			s.RegionStats = append(s.RegionStats, rs)
		}
	}
	if s.RegionStats == nil {
		s.RegionStats = []RegionStat{}
	}

	// 7天趋势
	trendRows, err := db.conn.Query(`
		SELECT DATE(created_at) as d,
			SUM(CASE WHEN result_code='000000' THEN 1 ELSE 0 END) as success,
			SUM(CASE WHEN result_code!='000000' THEN 1 ELSE 0 END) as fail
		FROM sign_logs WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
		GROUP BY DATE(created_at) ORDER BY d`)
	if err == nil {
		defer trendRows.Close()
		for trendRows.Next() {
			var ds DayStat
			trendRows.Scan(&ds.Date, &ds.Success, &ds.Fail)
			s.WeeklyTrend = append(s.WeeklyTrend, ds)
		}
	}
	if s.WeeklyTrend == nil {
		s.WeeklyTrend = []DayStat{}
	}

	return &s, nil
}

// ========== Geo Stats ==========

type GeoStat struct {
	Country string `json:"country"`
	Count   int    `json:"count"`
}

type GeoPoint struct {
	Account      string  `json:"account"`
	SerialNumber string  `json:"serial_number"`
	Platform     string  `json:"platform"`
	City         string  `json:"city"`
	Country      string  `json:"country"`
	ClientIP     string  `json:"client_ip"`
	ResultCode   string  `json:"result_code"`
	CreatedAt    string  `json:"created_at"`
	Lat          float64 `json:"lat"`
	Lon          float64 `json:"lon"`
}

func (db *DB) GetGeoStats() ([]GeoStat, error) {
	rows, err := db.conn.Query("SELECT country, COUNT(*) as cnt FROM sign_logs WHERE country != '' GROUP BY country ORDER BY cnt DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []GeoStat
	for rows.Next() {
		var s GeoStat
		rows.Scan(&s.Country, &s.Count)
		stats = append(stats, s)
	}
	if stats == nil {
		stats = []GeoStat{}
	}
	return stats, nil
}

func (db *DB) GetRecentSignPoints(limit int) ([]GeoPoint, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := db.conn.Query(
		`SELECT account, serial_number, platform, city, country, client_ip, result_code, created_at
		 FROM sign_logs WHERE country != '' ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []GeoPoint
	for rows.Next() {
		var p GeoPoint
		rows.Scan(&p.Account, &p.SerialNumber, &p.Platform, &p.City, &p.Country, &p.ClientIP, &p.ResultCode, &p.CreatedAt)
		points = append(points, p)
	}
	if points == nil {
		points = []GeoPoint{}
	}
	return points, nil
}

// ========== DB Stats ==========

func (db *DB) Stats() sql.DBStats {
	return db.conn.Stats()
}

// ========== Cleanup ==========

func (db *DB) CleanupUsedTokens() (sql.Result, error) {
	return db.conn.Exec("DELETE FROM tokens WHERE status='used'")
}

func (db *DB) CleanupUsedOTPs() (sql.Result, error) {
	return db.conn.Exec("DELETE FROM cotp WHERE status='used' OR status='inactive'")
}

func (db *DB) CleanupOldSignLogs(days int) (sql.Result, error) {
	return db.conn.Exec("DELETE FROM sign_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)", days)
}

func (db *DB) CleanupOldFlashLogs(days int) (sql.Result, error) {
	return db.conn.Exec("DELETE FROM flashlog WHERE time < DATE_SUB(NOW(), INTERVAL ? DAY)", days)
}

func (db *DB) CleanupOldLoginLogs(days int) (sql.Result, error) {
	return db.conn.Exec("DELETE FROM login_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)", days)
}

// ========== Login Logs ==========

func (db *DB) InsertLoginLog(account, clientIP, city, country, region, result string, lat, lon float64) {
	db.conn.Exec(
		"INSERT INTO login_logs (account, client_ip, city, country, region, result, lat, lon) VALUES (?,?,?,?,?,?,?,?)",
		account, clientIP, city, country, region, result, lat, lon,
	)
}

func (db *DB) GetLoginGeoStats() ([]GeoStat, error) {
	rows, err := db.conn.Query("SELECT country, COUNT(*) as cnt FROM login_logs WHERE country != '' GROUP BY country ORDER BY cnt DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var stats []GeoStat
	for rows.Next() {
		var s GeoStat
		rows.Scan(&s.Country, &s.Count)
		stats = append(stats, s)
	}
	if stats == nil {
		stats = []GeoStat{}
	}
	return stats, nil
}

type LoginGeoPoint struct {
	Account   string  `json:"account"`
	City      string  `json:"city"`
	Country   string  `json:"country"`
	ClientIP  string  `json:"client_ip"`
	Result    string  `json:"result"`
	CreatedAt string  `json:"created_at"`
	Lat       float64 `json:"lat"`
	Lon       float64 `json:"lon"`
}

func (db *DB) GetRecentLoginPoints(limit int) ([]LoginGeoPoint, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := db.conn.Query(
		`SELECT account, city, country, client_ip, result, created_at, lat, lon
		 FROM login_logs WHERE country != '' ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var points []LoginGeoPoint
	for rows.Next() {
		var p LoginGeoPoint
		rows.Scan(&p.Account, &p.City, &p.Country, &p.ClientIP, &p.Result, &p.CreatedAt, &p.Lat, &p.Lon)
		points = append(points, p)
	}
	if points == nil {
		points = []LoginGeoPoint{}
	}
	return points, nil
}

// ========== RCSM Token & Credentials ==========

func (db *DB) GetRCSMToken(server string) (string, error) {
	var token string
	err := db.conn.QueryRow("SELECT IFNULL(token,'') FROM rcsm_token WHERE server = ?", server).Scan(&token)
	return token, err
}

func (db *DB) UpdateRCSMToken(server, token string) error {
	_, err := db.conn.Exec(
		"INSERT INTO rcsm_token (server, token, time) VALUES (?, ?, NOW()) ON DUPLICATE KEY UPDATE token = VALUES(token), time = NOW()",
		server, token,
	)
	return err
}

type RCSMCredentials struct {
	User     string
	Password string
	Mac      string
}

func (db *DB) GetRCSMCredentials(server string) (*RCSMCredentials, error) {
	var c RCSMCredentials
	err := db.conn.QueryRow(
		"SELECT IFNULL(`user`,''), IFNULL(password,''), IFNULL(mac,'00-E0-4C-73-E7-47') FROM rcsm_ids WHERE LOWER(server) = LOWER(?)", server,
	).Scan(&c.User, &c.Password, &c.Mac)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// ========== RCSM Admin CRUD ==========

type RCSMAccount struct {
	ID       int    `json:"id"`
	Server   string `json:"server"`
	User     string `json:"user"`
	Password string `json:"password"`
	Mac      string `json:"mac"`
}

func (db *DB) ListRCSMAccounts() ([]RCSMAccount, error) {
	rows, err := db.conn.Query("SELECT id, server, IFNULL(`user`,''), IFNULL(password,''), IFNULL(mac,'00-E0-4C-73-E7-47') FROM rcsm_ids ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []RCSMAccount
	for rows.Next() {
		var a RCSMAccount
		rows.Scan(&a.ID, &a.Server, &a.User, &a.Password, &a.Mac)
		list = append(list, a)
	}
	if list == nil {
		list = []RCSMAccount{}
	}
	return list, nil
}

func (db *DB) CreateRCSMAccount(server, user, password, mac string) error {
	if mac == "" {
		mac = "00-E0-4C-73-E7-47"
	}
	_, err := db.conn.Exec(
		"INSERT INTO rcsm_ids (server, `user`, password, mac) VALUES (?, ?, ?, ?)",
		server, user, password, mac,
	)
	return err
}

func (db *DB) DeleteRCSMAccount(id int) error {
	_, err := db.conn.Exec("DELETE FROM rcsm_ids WHERE id = ?", id)
	return err
}

type RCSMTokenRecord struct {
	ID     int    `json:"id"`
	Server string `json:"server"`
	Token  string `json:"token"`
	Time   string `json:"time"`
}

func (db *DB) ListRCSMTokens() ([]RCSMTokenRecord, error) {
	rows, err := db.conn.Query("SELECT id, server, IFNULL(token,''), IFNULL(DATE_FORMAT(time,'%Y-%m-%d %H:%i:%s'),'') FROM rcsm_token ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []RCSMTokenRecord
	for rows.Next() {
		var t RCSMTokenRecord
		rows.Scan(&t.ID, &t.Server, &t.Token, &t.Time)
		list = append(list, t)
	}
	if list == nil {
		list = []RCSMTokenRecord{}
	}
	return list, nil
}

func (db *DB) DeleteRCSMToken(id int) error {
	_, err := db.conn.Exec("DELETE FROM rcsm_token WHERE id = ?", id)
	return err
}

// ========== RCSM Sign Keys ==========

type RCSMSignKey struct {
	ID        int    `json:"id"`
	WorkID    string `json:"work_id"`
	Token     string `json:"token"`
	Region    string `json:"region"`
	Status    string `json:"status"`
	Note      string `json:"note"`
	CreatedAt string `json:"created_at"`
}

func (db *DB) ListRCSMSignKeys() ([]RCSMSignKey, error) {
	rows, err := db.conn.Query("SELECT id, work_id, token, region, status, IFNULL(note,''), IFNULL(DATE_FORMAT(created_at,'%Y-%m-%d %H:%i:%s'),'') FROM rcsm_sign_keys ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []RCSMSignKey
	for rows.Next() {
		var k RCSMSignKey
		rows.Scan(&k.ID, &k.WorkID, &k.Token, &k.Region, &k.Status, &k.Note, &k.CreatedAt)
		list = append(list, k)
	}
	if list == nil {
		list = []RCSMSignKey{}
	}
	return list, nil
}

func (db *DB) CreateRCSMSignKey(workID, token, region, note string) error {
	_, err := db.conn.Exec(
		"INSERT INTO rcsm_sign_keys (work_id, token, region, note) VALUES (?, ?, ?, ?)",
		workID, token, region, note,
	)
	return err
}

func (db *DB) UpdateRCSMSignKey(id int, workID, token, region, note, status string) error {
	_, err := db.conn.Exec(
		"UPDATE rcsm_sign_keys SET work_id=?, token=?, region=?, note=?, status=? WHERE id=?",
		workID, token, region, note, status, id,
	)
	return err
}

func (db *DB) ToggleRCSMSignKey(id int, status string) error {
	_, err := db.conn.Exec("UPDATE rcsm_sign_keys SET status=? WHERE id=?", status, id)
	return err
}

func (db *DB) DeleteRCSMSignKey(id int) error {
	_, err := db.conn.Exec("DELETE FROM rcsm_sign_keys WHERE id = ?", id)
	return err
}

// VerifyRCSMSignKey 验证 work_id + token，返回 region 和 error
func (db *DB) VerifyRCSMSignKey(workID, token string) (string, error) {
	var region string
	err := db.conn.QueryRow(
		"SELECT region FROM rcsm_sign_keys WHERE work_id=? AND token=? AND status='active' LIMIT 1",
		workID, token,
	).Scan(&region)
	if err != nil {
		return "", fmt.Errorf("invalid work_id or token")
	}
	return region, nil
}
