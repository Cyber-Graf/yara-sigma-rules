rule DCRAT_Mutex_AMSI_UA
{
    meta:
        description = "Detects DCRAT payload with known mutex, AMSI bypass and network signature"
        author = "Cyber Graf"
        reference = "FortiGuard Labs, 2025"
        version = "1.1"
        license = "CC BY 4.0"
        threat_name = "DCRAT / Pastebin Loader Variant"

    strings:
        $mutex = "DcRatMutex_qwqdanchun" ascii
        $amsi = "AmsiScanBuffer" ascii nocase
        $dll = "amsi.dll" ascii
        $task = "/create /f /sc onlogon" ascii
        $ua = "Mozilla/5.0 Windows NT 10.0" ascii

    condition:
        uint16(0) == 0x5A4D and 2 of ($mutex, $amsi, $dll, $task, $ua)
}
