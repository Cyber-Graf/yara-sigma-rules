import "pe"

rule ShadowSyndicate_Stealth_Dropper_v1_1
{
    meta:
        description = "Detects ShadowSyndicate dropper mimicking PDF updater with PE and C2 artifacts"
        author = "Cyber Graf"
        version = "1.1
        hash1 = "e8a90b6e564d394f3ae6a6d69e45bcab"
        reference = "FortiGuard Labs – Taiwan Targeting"
        license = "CC BY 4.0"

    strings:
        $s1 = "pdfupdate.exe" ascii
        $s2 = "PayloadStage2.dat" ascii
        $s3 = "XOR_KEY=" ascii
        $s4 = "Content-Disposition: attachment;" ascii
        $s5 = /[A-Za-z0-9+/=]{200,}/ ascii
        $c2 = "doc.securemailbox.cc" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 800KB and
        pe.number_of_sections <= 6 and
        (
            pe.imphash() == "d41d8cd98f00b204e9800998ecf8427e" or
            pe.imports("kernel32.dll", "WriteFile")
        ) and
        3 of ($s*) and $c2
}
