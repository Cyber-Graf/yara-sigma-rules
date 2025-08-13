rule WinRAR_CVE2025_6218_autostart_exe
{
    meta:
        description = "Detects malicious executables created via CVE-2025-6218 in WinRAR that drop into Windows Startup folders"
        author = "Cyber Graf"
        reference = "BI.ZONE — Paper Werewolf атакует Россию с использованием уязвимости нулевого дня в WinRAR"
        version = "1.0"
        license = "CC BY 4.0"
        threat_name = "Paper Werewolf / GOFFEE"

    strings:
        $s1 = "xpsrchvw71.exe" nocase
        $s2 = "xpsrchvw72.exe" nocase
        $s3 = "xpsrchvw73.exe" nocase
        $s4 = "xpsrchvw74.exe" nocase
        $path1 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" nocase

    condition:
        (uint16(0) == 0x5A4D) and any of ($s*) and $path1
}