package database

import (
	"database/sql"
	"fmt"

	"go-server/internal/config"

	_ "github.com/go-sql-driver/mysql"
)

type DB struct {
	conn *sql.DB
}

func New(cfg config.DatabaseConfig) (*DB, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=true",
		cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.DBName)
	conn, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	if err := conn.Ping(); err != nil {
		return nil, err
	}
	conn.SetMaxOpenConns(20)
	conn.SetMaxIdleConns(5)

	db := &DB{conn: conn}
	if err := db.autoMigrate(); err != nil {
		return nil, fmt.Errorf("auto migrate: %w", err)
	}
	return db, nil
}

func (db *DB) autoMigrate() error {
	tables := []string{
		`CREATE TABLE IF NOT EXISTS actived_server (
			id int NOT NULL AUTO_INCREMENT,
			server_id int DEFAULT NULL,
			region varchar(50) DEFAULT NULL,
			token text,
			activeBy varchar(50) DEFAULT NULL,
			PRIMARY KEY (id)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		`CREATE TABLE IF NOT EXISTS servers (
			id int NOT NULL AUTO_INCREMENT,
			username varchar(100) DEFAULT NULL,
			password varchar(100) DEFAULT NULL,
			mac varchar(50) DEFAULT NULL,
			region varchar(50) DEFAULT NULL,
			PRIMARY KEY (id)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		`CREATE TABLE IF NOT EXISTS tokens (
			id int NOT NULL AUTO_INCREMENT,
			generated_token varchar(255) DEFAULT NULL,
			original_token text,
			status varchar(20) DEFAULT 'unused',
			PRIMARY KEY (id),
			KEY idx_generated_token (generated_token)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		`CREATE TABLE IF NOT EXISTS cotp (
			id int NOT NULL AUTO_INCREMENT,
			otp text,
			status varchar(20) DEFAULT 'active',
			created_at datetime DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		`CREATE TABLE IF NOT EXISTS sign_logs (
			id int NOT NULL AUTO_INCREMENT,
			platform varchar(100) DEFAULT '',
			chipset varchar(100) DEFAULT '',
			serial_number varchar(100) DEFAULT '',
			account varchar(200) DEFAULT '',
			client_ip varchar(50) DEFAULT '',
			city varchar(100) DEFAULT '',
			country varchar(100) DEFAULT '',
			region varchar(50) DEFAULT '',
			result_code varchar(20) DEFAULT '',
			result_msg text,
			created_at datetime DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			KEY idx_created_at (created_at)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		`CREATE TABLE IF NOT EXISTS sign_forwards (
			id int NOT NULL AUTO_INCREMENT,
			region varchar(50) NOT NULL,
			target_url varchar(500) NOT NULL,
			enabled tinyint(1) DEFAULT 1,
			PRIMARY KEY (id),
			UNIQUE KEY idx_region (region)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS cert (
			id int NOT NULL AUTO_INCREMENT,
			Region varchar(50) NOT NULL,
			DeviceId text NOT NULL,
			IV varchar(100) NOT NULL,
			CipherInfo text NOT NULL,
			PRIMARY KEY (id),
			UNIQUE KEY idx_region (Region)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		`CREATE TABLE IF NOT EXISTS flashlog (
			id int NOT NULL AUTO_INCREMENT,
			username varchar(200) DEFAULT '',
			ticket varchar(200) DEFAULT '',
			sn varchar(200) DEFAULT '',
			projectNo varchar(100) DEFAULT '',
			code varchar(50) DEFAULT '',
			msg text,
			type varchar(50) DEFAULT '',
			time datetime DEFAULT NULL,
			platform varchar(100) DEFAULT '',
			PRIMARY KEY (id)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		`CREATE TABLE IF NOT EXISTS login_logs (
			id int NOT NULL AUTO_INCREMENT,
			account varchar(200) DEFAULT '',
			client_ip varchar(50) DEFAULT '',
			city varchar(100) DEFAULT '',
			country varchar(100) DEFAULT '',
			region varchar(50) DEFAULT '',
			result varchar(20) DEFAULT '',
			lat double DEFAULT 0,
			lon double DEFAULT 0,
			created_at datetime DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			KEY idx_created_at (created_at)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		`CREATE TABLE IF NOT EXISTS new_server (
			server varchar(100) NOT NULL,
			signurl varchar(500) DEFAULT '',
			region varchar(50) DEFAULT '',
			workid varchar(100) DEFAULT '',
			token text,
			credit double DEFAULT 0,
			status varchar(20) DEFAULT 'Online',
			PRIMARY KEY (server)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		`CREATE TABLE IF NOT EXISTS rcsm_token (
			id int NOT NULL AUTO_INCREMENT,
			server varchar(100) NOT NULL,
			token text,
			time datetime DEFAULT NULL,
			PRIMARY KEY (id),
			UNIQUE KEY idx_server (server)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		`CREATE TABLE IF NOT EXISTS rcsm_sign_keys (
			id int NOT NULL AUTO_INCREMENT,
			work_id varchar(100) NOT NULL,
			token varchar(255) NOT NULL,
			region varchar(50) DEFAULT 'India',
			status varchar(20) DEFAULT 'active',
			note varchar(200) DEFAULT '',
			created_at datetime DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			UNIQUE KEY idx_work_token (work_id, token)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		`CREATE TABLE IF NOT EXISTS rcsm_ids (
			id int NOT NULL AUTO_INCREMENT,
			server varchar(100) NOT NULL,
			user varchar(200) DEFAULT '',
			password varchar(200) DEFAULT '',
			PRIMARY KEY (id),
			UNIQUE KEY idx_server (server)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
	}

	for _, ddl := range tables {
		if _, err := db.conn.Exec(ddl); err != nil {
			return err
		}
	}

	// 预置 cert 数据（从 PHP 配置提取）
	certSeeds := []struct{ region, deviceId, iv, cipherInfo string }{
		{
			"India",
			"AGonPglxL4XCTzjpn9MJVUJ0qHLzPBEA715+V0JZ028=",
			"jyLQkVmnCd/459fm",
			`{"dfs-ms":{"protectedKey":"FBmp8zHGh3+g+UX+sQl7fV2OVgZe/rrrmn8wr2hjnCbiZM6NIA9RhvfekZRFihhXfMlCJCNFQYOzQO7Po/fBq7igk5VIPyDkhDLuQdXbN1zCD9s1K0MSz6bDMLC2rxhrDsqUekG6w9C1ioJYM9UKKp0qyONNVd62I/v6hvF06chXF7RLUY9L/aVQBa01pTnoCP2zMp2OKH4sm5M6GleMMe/UU9jNvW3mz6+WhTrCAZ90nZNFwblE7eL5SpE6Wchc+TjdEK1jc4u77TUHBbf+NXXOG3H4tsKIyQkqGGAXekPEyyBPB2rW4imruW5hS7BLo2MwBwm4pvlYwPCKPspCyw==","certVersion":"1661156498682","version":"1762176616"}}`,
		},
		{
			"Eu",
			"kMeTYcyvdnfL60wlKYdXFYzg5LjQ9r8wp1Njzgiza1s=",
			"O+cOaeEao7hCSBtc",
			`{"dfs-ms":{"protectedKey":"WI5Cm+fbleSuzmskTX0gAa7hgim4jVWVF9nKVClAQqjA7Hc/fzp+BjDGzNDl+/kNWJOGOR2Hkuqnn/RuVDIemEv6pqrMDhmjIdLSjiK8vE/pBxlZb95JF7+ntgqSgya9UGnYu5ZXoiowCUJHMS3DW1iPVNMo872C394z0/sXPHLedM83oRfOE93slbWNNgq9LK/2JW9VkLVi5PbYQV5ZTmu1/glK2aNg+w4yNu4h//wDT2pFhDiORNFc2e/BuzpNDt8/A0ND5GMX0WrIA7WhH8O9+2uuEu2zTomQSvZU1TQsdlm8mxs8w+5wNzmDD7RAp90Lsz1vljEtoaL9uGmg9w==","certVersion":"1661242029662","version":"1762176371"}}`,
		},
		{
			"Europe",
			"kMeTYcyvdnfL60wlKYdXFYzg5LjQ9r8wp1Njzgiza1s=",
			"O+cOaeEao7hCSBtc",
			`{"dfs-ms":{"protectedKey":"WI5Cm+fbleSuzmskTX0gAa7hgim4jVWVF9nKVClAQqjA7Hc/fzp+BjDGzNDl+/kNWJOGOR2Hkuqnn/RuVDIemEv6pqrMDhmjIdLSjiK8vE/pBxlZb95JF7+ntgqSgya9UGnYu5ZXoiowCUJHMS3DW1iPVNMo872C394z0/sXPHLedM83oRfOE93slbWNNgq9LK/2JW9VkLVi5PbYQV5ZTmu1/glK2aNg+w4yNu4h//wDT2pFhDiORNFc2e/BuzpNDt8/A0ND5GMX0WrIA7WhH8O9+2uuEu2zTomQSvZU1TQsdlm8mxs8w+5wNzmDD7RAp90Lsz1vljEtoaL9uGmg9w==","certVersion":"1661242029662","version":"1762176371"}}`,
		},
		{
			"China",
			"Zels7uBfH9HG6wLUYEt8KAWpLVZ4f1NSOpoA1/Kl45Y=",
			"kNYUxMmX/6DkQdQ5",
			`{"dfs-ms":{"protectedKey":"J/FMG2M7MbgOJ8UFI7T/ZKdLeVsZqL+mjroKg62inn03RYR4OWavnQYifMwVrNury9T3YoxvMOR71ebj38sSzFaiJ8nhWhYz/ZMzfbRSz0HHR4RZvWJYS1xPxyhaldQRL/YiRqwaUKBpCOfslksBhOALgUpHZaTsilO3d5k5Engc8LSU4uHjDSv/RK3CSAMRL/nzwq8UEl0h3jI8jfVQJ6ZWotUXWkm050e50U8Qk8vDcIlhkuWTDDY7xHiXDJ6IeyYlB/VyIqsKwfTsOBtR5f74MhRi+NkgxVY59sYBmBO0XTIsl0dsiKczb5OdAnYQ/dc1KXvhf3WzWl75nRtk+Q==","certVersion":"1652408536857","version":"1762176135"}}`,
		},
		{
			"Singapore",
			"rPYeZ+Yk56QIAdYoYVG6yQhB4lLmqg0SfTX9UYBnTfw=",
			"Z9P+0XgSw1m40cCu",
			`{"dfs-ms":{"protectedKey":"A0QRtOwt1pgv5kxuTKug+RQYi8mOZ/oK/eVJNFNx1S4EP6CGk6X/Dfy2tpknz/2HTMlGFNxIa3QaFRnbVBltM3kQ6alXmQjv6jmuWQfbSm/CX2EVJfpVRY/ng4BOzcxKaURncrm0s0yiEr7C8p4uPpdECPIRbbSVBxo1xCx1UGzVwbpwcXGKFq+zhm5v9inL/UcTRNfnpad5ntViVCTFAnPeQxovE16eDLUW89RFzdwk35vVSkqYWROKUrvsFmIMdr3hFnRq4KE9rxVOYKvdUDyBLGQEHimaPX/e7t1/J1FyVDMmdxhp0mJ7s72PuRA6Q+GkK0x84qjZ6S+WVkoPkQ==","certVersion":"1661149845669","version":"1762176717"}}`,
		},
	}
	for _, c := range certSeeds {
		db.conn.Exec(
			"INSERT IGNORE INTO cert (Region, DeviceId, IV, CipherInfo) VALUES (?, ?, ?, ?)",
			c.region, c.deviceId, c.iv, c.cipherInfo,
		)
	}

	// 兼容旧表：给 cotp 加 status / created_at / region 字段（忽略已存在错误）
	db.conn.Exec("ALTER TABLE cotp ADD COLUMN status varchar(20) DEFAULT 'active'")
	db.conn.Exec("ALTER TABLE cotp ADD COLUMN created_at datetime DEFAULT CURRENT_TIMESTAMP")
	db.conn.Exec("ALTER TABLE cotp ADD COLUMN region varchar(50) DEFAULT 'Eu'")

	// 给 sign_logs 加 lat/lon/response 字段
	db.conn.Exec("ALTER TABLE sign_logs ADD COLUMN lat double DEFAULT 0")
	db.conn.Exec("ALTER TABLE sign_logs ADD COLUMN lon double DEFAULT 0")
	db.conn.Exec("ALTER TABLE sign_logs ADD COLUMN response text")

	// 给 actived_server 加 workid 和 sign_url 字段
	db.conn.Exec("ALTER TABLE actived_server ADD COLUMN workid varchar(100) DEFAULT 'NBSQ17RNA130T'")
	db.conn.Exec("ALTER TABLE actived_server ADD COLUMN sign_url varchar(500) DEFAULT 'https://gsmtgt.me/api/sign/sign'")
	// sign_mode: 'auto'(智能识别), 'new'(仅新版AES转发), 'rcsm'(仅旧版RCSM)
	db.conn.Exec("ALTER TABLE actived_server ADD COLUMN sign_mode varchar(20) DEFAULT 'auto'")

	// rcsm_ids 加 mac 字段（每个 RCSM 账号绑定的 MAC 地址）
	db.conn.Exec("ALTER TABLE rcsm_ids ADD COLUMN mac varchar(50) DEFAULT '00-E0-4C-73-E7-47'")

	// 插入默认区域配置（如果不存在）
	var count int
	db.conn.QueryRow("SELECT COUNT(*) FROM actived_server WHERE id = 1").Scan(&count)
	if count == 0 {
		db.conn.Exec("INSERT INTO actived_server (id, server_id, region, token, activeBy) VALUES (1, 1, 'India', '', 'ByToken')")
	}

	return nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}

// ActivedServer 表结构
type ActivedServer struct {
	ServerID int
	Region   string
	Token    string
	ActiveBy string
	WorkID   string
	SignURL  string
	SignMode string // "auto", "new", "rcsm"
}

func (db *DB) GetActivedServer() (*ActivedServer, error) {
	var s ActivedServer
	err := db.conn.QueryRow(
		"SELECT server_id, region, IFNULL(token,''), IFNULL(activeBy,'ByToken'), IFNULL(workid,'NBSQ17RNA130T'), IFNULL(sign_url,'https://gsmtgt.me/api/sign/sign'), IFNULL(sign_mode,'auto') FROM actived_server WHERE id = 1",
	).Scan(&s.ServerID, &s.Region, &s.Token, &s.ActiveBy, &s.WorkID, &s.SignURL, &s.SignMode)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (db *DB) GetActivedServerRegion() (string, error) {
	var region string
	err := db.conn.QueryRow("SELECT region FROM actived_server WHERE id = 1").Scan(&region)
	return region, err
}

// ServerCredentials 服务器凭据
type ServerCredentials struct {
	Username string
	Password string
	Mac      string
	Region   string
}

func (db *DB) GetServerCredentials(serverID int) (*ServerCredentials, error) {
	var c ServerCredentials
	err := db.conn.QueryRow(
		"SELECT username, password, mac, region FROM servers WHERE id = ?", serverID,
	).Scan(&c.Username, &c.Password, &c.Mac, &c.Region)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// Token 管理
func (db *DB) FindOriginalToken(generatedToken string) (string, error) {
	var originalToken string
	err := db.conn.QueryRow(
		"SELECT original_token FROM tokens WHERE generated_token = ? AND status = 'unused' LIMIT 1",
		generatedToken,
	).Scan(&originalToken)
	if err != nil {
		return "", err
	}
	return originalToken, nil
}

func (db *DB) InsertToken(generatedToken, originalToken string) error {
	_, err := db.conn.Exec(
		"INSERT INTO tokens (generated_token, original_token, status) VALUES (?, ?, 'unused')",
		generatedToken, originalToken,
	)
	return err
}

func (db *DB) MarkTokenUsed(generatedToken string) error {
	_, err := db.conn.Exec(
		"UPDATE tokens SET status = 'used' WHERE generated_token = ?",
		generatedToken,
	)
	return err
}

// OTP
func (db *DB) GetOTP(id int) (string, error) {
	var otp string
	err := db.conn.QueryRow("SELECT otp FROM cotp WHERE id = ?", id).Scan(&otp)
	return otp, err
}
