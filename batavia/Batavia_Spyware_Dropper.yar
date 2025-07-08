rule Batavia_Spyware_Dropper
{
    meta:
        description = "Detects Batavia spyware delivery scripts and payload"
        author = "Cyber Graf"
        version = "1.0"
        reference = "Securelist, 2025"
        license = "CC BY 4.0"
        threat_family = "Batavia"

    strings:
        $ps1 = "Invoke-WebRequest" ascii
        $ps2 = "curl -o" ascii
        $ps3 = "ftp.exe" ascii
        $s1  = "C:\\Users\\Public\\Libraries\\" ascii
        $s2  = "cmd.exe /c del" ascii
        $reg = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $vbs = "CreateObject(\"Wscript.Shell\")" ascii

    condition:
        3 of ($*)
}