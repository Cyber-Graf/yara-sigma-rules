rule CobaltStrike_HTTP_Beacon
{
    meta:
        description = "Detects common Cobalt Strike HTTP beacon patterns"
        author = "Cyber Graf"
        reference = "APT41 Africa Campaign, Securelist"
        version = "1.2"
        license = "CC BY 4.0"
        threat_name = "Cobalt Strike"

    strings:
        $s1 = "MZ"
        $ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" ascii
        $hdr = "Accept-Language: en-US,en;q=0.5" ascii
        $json = "{ \"id\"" ascii
        $key = "session_key=" ascii

    condition:
        uint16(0) == 0x5A4D and all of ($ua, $hdr, $json)
}