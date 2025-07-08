rule Braodo_Telegram_Stealer
{
    meta:
        description = "Detects Braodo stealer variant using Telegram API for exfiltration"
        author = "Cyber Graf"
        version = "1.0"
        license = "CC BY 4.0"
        reference = "ANY.RUN, June 2025"

    strings:
        $t1 = "api.telegram.org/bot" ascii
        $t2 = "sendDocument" ascii
        $t3 = "metamask" ascii nocase
        $t4 = "wallet.dat" ascii

    condition:
        uint16(0) == 0x5A4D and 2 of ($t*)
}
