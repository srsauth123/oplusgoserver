package service

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"go-server/internal/config"
)

type TelegramService struct {
	cfg config.TelegramConfig
}

func NewTelegramService(cfg config.TelegramConfig) *TelegramService {
	return &TelegramService{cfg: cfg}
}

func escapeMarkdownV2(text string) string {
	chars := []string{"_", "*", "[", "]", "(", ")", "~", "`", ">", "#", "+", "-", "=", "|", "{", "}", ".", "!"}
	for _, c := range chars {
		text = strings.ReplaceAll(text, c, "\\"+c)
	}
	return text
}

func (t *TelegramService) SendSignNotification(platform, chipset, serial, account, ip, city, country, flag, time, response string) error {
	if t.cfg.BotToken == "" || t.cfg.ChatID == "" {
		return nil
	}

	escapedResponse := response
	if len(escapedResponse) > 1000 {
		escapedResponse = escapedResponse[:1000]
	}

	msg := fmt.Sprintf("*🔔 OPPO SIGN INFO 🔔*\n\n"+
		"*📱 Platform:* `%s`\n"+
		"*🔧 Chipset:* `%s`\n"+
		"*🔢 Serial Number:* `%s`\n"+
		"*👤 Account:* `%s`\n"+
		"*🌐 IP:* `%s`\n"+
		"*📍 Location:* `%s, %s` %s\n"+
		"*📅 Time:* `%s`\n\n"+
		"*📨 API Response:*\n```\n%s\n```",
		escapeMarkdownV2(platform),
		escapeMarkdownV2(chipset),
		escapeMarkdownV2(serial),
		escapeMarkdownV2(account),
		escapeMarkdownV2(ip),
		escapeMarkdownV2(city),
		escapeMarkdownV2(country),
		flag,
		escapeMarkdownV2(time),
		escapeMarkdownV2(escapedResponse),
	)

	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.cfg.BotToken)
	resp, err := http.PostForm(apiURL, url.Values{
		"chat_id":    {t.cfg.ChatID},
		"text":       {msg},
		"parse_mode": {"MarkdownV2"},
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
