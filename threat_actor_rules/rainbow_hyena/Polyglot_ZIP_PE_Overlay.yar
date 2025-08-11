rule Polyglot_ZIP_PE_Overlay
{
    meta:
        description = "Detects polyglot ZIP files with PE overlay (MZ in appended data)"
        author = "Cyber Graf"
        version = "1.0"
        license = "CC BY 4.0"
        threat_name = "Polyglot PE Overlay"

    strings:
        $zip = { 50 4B 03 04 }                // ZIP file header
        $mz = { 4D 5A }                       // PE MZ header
        $pe = "This program cannot be run" ascii

    condition:
        $zip at 0 and for any i in (1..#mz) : (@mz[i] > 30000 and $pe)
}