rule SilentCryptoMiner_F6_Payload
{
    meta:
        description = "Detects modified miner payloads with PowerShell and DLL sideloading from F6 Flibusta case"
        author = "Cyber Graf"
        reference = "F6, 2025"
        version = "1.0"
        license = "CC BY 4.0"
        threat_name = "SilentCryptoMiner variant"

    strings:
        $s1 = "SilentCryptoMiner" ascii nocase
        $s2 = "Add-MpPreference" ascii
        $s3 = "Set-MpPreference" ascii
        $s4 = "SbieDll.dll" ascii
        $s5 = "wusa.exe /uninstall /kb:890830" ascii
        $url1 = "https://m4yuri.online/better/api/endpoint.php" ascii
        $url2 = "http://91.149.239.161:53" ascii

    condition:
        uint16(0) == 0x5A4D and (3 of ($s*) or any of ($url*))
}