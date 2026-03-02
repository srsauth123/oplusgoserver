package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
)

// EncryptRSAPublicKey 使用 RSA 公钥分块加密（PKCS1v15），返回 base64
func EncryptRSAPublicKey(pubKeyPEM string, plaintext []byte) (string, error) {
	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("not an RSA public key")
	}

	keySize := rsaPub.Size()
	bufferSize := keySize - 11

	var encrypted []byte
	for offset := 0; offset < len(plaintext); offset += bufferSize {
		end := offset + bufferSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		chunk, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, plaintext[offset:end])
		if err != nil {
			return "", fmt.Errorf("encrypt chunk: %w", err)
		}
		encrypted = append(encrypted, chunk...)
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DecryptRSAPrivateKey 使用 RSA 私钥分块解密（PKCS1v15）
func DecryptRSAPrivateKey(privKeyPEM string, ciphertextB64 string) ([]byte, error) {
	block, _ := pem.Decode([]byte(privKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	rsaPriv, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	keySize := rsaPriv.Size()
	var decrypted []byte
	for offset := 0; offset < len(ciphertext); offset += keySize {
		end := offset + keySize
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		chunk, err := rsa.DecryptPKCS1v15(rand.Reader, rsaPriv, ciphertext[offset:end])
		if err != nil {
			return nil, fmt.Errorf("decrypt chunk: %w", err)
		}
		decrypted = append(decrypted, chunk...)
	}
	return decrypted, nil
}

// DecryptAES256GCM 解密 AES-256-GCM（ciphertext 末尾 16 字节为 tag）
func DecryptAES256GCM(ciphertextB64, keyB64, nonceB64 string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	aesGCM, err := cipher.NewGCMWithNonceSize(block, len(nonce))
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	// ciphertext 格式：加密数据 + 16字节 tag（PHP 里是 ciphertext.tag 拼接后 base64）
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm open: %w", err)
	}
	return plaintext, nil
}

// EncryptAES256GCM 加密 AES-256-GCM，返回 base64(ciphertext + tag)
func EncryptAES256GCM(plaintext []byte, keyB64, nonceB64 string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return "", fmt.Errorf("decode key: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return "", fmt.Errorf("decode nonce: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("new cipher: %w", err)
	}
	aesGCM, err := cipher.NewGCMWithNonceSize(block, len(nonce))
	if err != nil {
		return "", fmt.Errorf("new gcm: %w", err)
	}

	sealed := aesGCM.Seal(nil, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// MD5Hash 计算 MD5
func MD5Hash(content string) string {
	h := md5.Sum([]byte(content))
	return hex.EncodeToString(h[:])
}

// BuildRCSMSign 构造 RCSM 签名
// methodName: 如 /api/tools/login
// secret: 区域对应的密钥
// params: 参与签名的字段（不含 sign）
func BuildRCSMSign(methodName, secret string, params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	sb.WriteString(methodName)
	sb.WriteString("\n")
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteString("=")
		sb.WriteString(params[k])
		sb.WriteString("\n")
	}
	sb.WriteString(secret)
	return MD5Hash(sb.String())
}
