rule Prometei_Linux_UPX_JSONTrailer
{
    meta:
        description = "Detects Prometei botnet ELF binary with UPX packing and embedded JSON config"
        author = "Cyber Graf"
        reference = "Unit42: Prometei Resurgence (2025)"
        version = "1.2"
        license = "CC BY 4.0"

    strings:
        $elf = { 7F 45 4C 46 }              // ELF header
        $upx = "UPX!" ascii                 // UPX-packed
        $json_key1 = "\"ver\"" ascii
        $json_key2 = "\"c2\"" ascii
        $json_key3 = "\"a\":\"x86_64\"" ascii

    condition:
        $elf and $upx and 2 of ($json_key*)
}