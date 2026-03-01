# Go Server - OPPO/Realme 工具代理服务

用 Go 语言重写的 PHP 后端服务，保持所有 API 路径不变。

## API 路由

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/platform/login` | DFS 平台登录（AES-256-GCM 解密 + OTP 验证 + Token 映射） |
| POST | `/api/tools/login` | RCSM 工具登录（RSA 加解密 + MD5 签名） |
| POST | `/api/tools/sign` | RCSM 工具签名（RSA 加解密 + MD5 签名） |
| POST | `/api/sign/sign` | 核心签名接口（Token 映射 + 转发 + Telegram 通知） |
| POST | `/api/sign/login` | 签名登录（OTP 验证 + 静态响应） |
| POST | `/api/flash/get_versions` | ROM 固件版本查询（代理转发） |
| GET/POST | `/crypto/cert/upgrade` | 证书分发（按区域动态返回） |
| GET/POST | `/crypto/cert/upgradein` | India 区域证书（固定） |

## 快速开始

### 1. 安装依赖

```bash
cd go-server
go mod tidy
```

### 2. 配置

编辑 `config.yaml`，设置：
- 数据库连接信息
- Telegram Bot Token 和 Chat ID
- OTP 验证地址（verify_url）
- 签名服务器 IP
- RSA 密钥

### 3. 运行

```bash
go run main.go
# 或指定配置文件
go run main.go /path/to/config.yaml
```

### 4. 编译

```bash
go build -o server main.go
./server
```

## 数据库表结构

```sql
CREATE TABLE `actived_server` (
  `id` int NOT NULL AUTO_INCREMENT,
  `server_id` int DEFAULT NULL,
  `region` varchar(50) DEFAULT NULL,
  `token` text,
  `activeBy` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

CREATE TABLE `servers` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(100) DEFAULT NULL,
  `password` varchar(100) DEFAULT NULL,
  `mac` varchar(50) DEFAULT NULL,
  `region` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

CREATE TABLE `tokens` (
  `id` int NOT NULL AUTO_INCREMENT,
  `generated_token` varchar(255) DEFAULT NULL,
  `original_token` text,
  `status` varchar(20) DEFAULT 'unused',
  PRIMARY KEY (`id`),
  KEY `idx_generated_token` (`generated_token`)
);

CREATE TABLE `cotp` (
  `id` int NOT NULL AUTO_INCREMENT,
  `otp` text,
  PRIMARY KEY (`id`)
);
```

## 技术栈

- **Go 1.21+**
- **Gin** — HTTP 路由框架
- **go-sql-driver/mysql** — MySQL 驱动
- **标准库** — crypto/rsa, crypto/aes, crypto/cipher 等
