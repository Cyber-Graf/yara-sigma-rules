rule Room155_Stealerium_DiscordWebhook
{
    meta:
        description = "Detects Stealerium sample with Discord webhook exfiltration used by room155"
        author = "CyberGraf"
        version = "1.2"
        hash1 = "6a851b7e10b8a5b6772ba6f75fdd575d"
        reference = "F6 report: room155"
        license = "CC BY 4.0"

    strings:
        $s1 = "discord.com/api/webhooks/" ascii wide
        $s2 = "Stealerium" ascii wide
        $s3 = "Authorization: Bot " ascii
        $s4 = "https://ipinfo.io/json" ascii
        $s5 = "Victim Info:" ascii

    condition:
        uint16(0) == 0x5A4D and filesize < 2MB and
        3 of ($s*)
}