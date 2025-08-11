rule Polyglot_ZIP_PE_PhantomRemote
{
    meta:
        description = "Detects polyglot ZIP files with embedded PE (DLL dropper from Rainbow Hyena)"
        author = "Cyber Graf"
        reference = "BI.ZONE — Rainbow Hyena 2025"
        version = "1.0"
        license = "CC BY 4.0"
        threat_name = "Polyglot Dropper"

    strings:
        $zip_header = { 50 4B 03 04 }          // ZIP local file header
        $pe_header = { 4D 5A }                 // 'MZ' PE signature
        $ua1 = "YandexCloud/1.0" ascii
        $ua2 = "MicrosoftAppStore/2001.0" ascii
        $entry = "EntryPoint" ascii
        $ps = "cmd.exe /u /c" ascii

    condition:
        $zip_header at 0 and $pe_header in (100..10000) and 2 of ($ua1, $ua2, $entry, $ps)
}