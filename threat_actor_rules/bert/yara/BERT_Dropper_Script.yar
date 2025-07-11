rule BERT_Dropper_Script
{
    meta:
        description = "Detects BAT or PowerShell dropper used by BERT ransomware"
        author = "Cyber Graf"
        license = "CC BY 4.0"
        reference = "Trend Micro, July 2025"

    strings:
        $s1 = "vssadmin delete shadows" ascii
        $s2 = "wmic shadowcopy delete" ascii
        $s3 = "del *.bak /f /s /q" ascii
        $s4 = ".bert" ascii

    condition:
        2 of ($s*)
}
