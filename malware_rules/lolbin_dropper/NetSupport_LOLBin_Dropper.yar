rule NetSupport_LOLBin_Dropper
{
    meta:
        description = "Detects NetSupport RAT dropped via LOLBins and BAT obfuscation"
        author = "Cyber Graf"
        version = "1.0"
        reference = "ANY.RUN, June 2025"
        license = "CC BY 4.0"

    strings:
        $b1 = "mshta.exe vbscript:" ascii
        $b2 = "curl -o" ascii
        $b3 = "NetSupport.exe" ascii

    condition:
        2 of ($b*)
}
