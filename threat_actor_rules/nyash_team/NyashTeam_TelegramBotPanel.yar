rule NyashTeam_TelegramBotPanel
{
    meta:
        description = "Detects PHP-based Telegram bot control panels used by NyashTeam"
        author = "Cyber Graf"
        version = "1.0"
        license = "CC BY 4.0"

    strings:
        $p1 = "api.telegram.org/bot" ascii
        $p2 = "insert into telegram_logs" ascii
        $p3 = "bot_token" ascii
        $p4 = "chat_id" ascii
        $p5 = "curl_setopt" ascii

    condition:
        any of ($p*)
}