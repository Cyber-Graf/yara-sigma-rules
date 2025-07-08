rule SnakeKeylogger_JSADebugd_Sideloading
{
    meta:
        description = "Detects Snake Keylogger via DLL sideloading abusing jsadebugd.exe and InstallUtil.exe"
        author = "Cyber Graf"
        version = "1.0"
        reference = "Lab52, 2025"
        license = "CC BY 4.0"
        threat_name = "Snake Keylogger"

    strings:
        $s1 = "reallyfreegeoip.org" ascii
        $s2 = "checkip.dyndns.org" ascii
        $s3 = "%USERPROFILE%\\SystemRootDoc" wide
        $s4 = "cmd.exe /C start" ascii
        $dll = "concrt141.dll" ascii
        $inject = "InstallUtil.exe" ascii
        $persist = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide

    condition:
        uint16(0) == 0x5A4D and 3 of ($s*)
}
