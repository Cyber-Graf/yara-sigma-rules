rule Havoc_C2_Shellcode_Signature
{
    meta:
        description = "Detects Havoc C2 payloads with InlineExecuteAssembly, BOF and C2 markers"
        author = "Cyber Graf"
        reference = "FortiGuard Labs, 2025"
        version = "1.1"
        license = "CC BY 4.0"
        threat_name = "Havoc C2 RAT"

    strings:
        $s1 = "InlineExecuteAssembly" ascii nocase
        $s2 = "BOF_Invoke" ascii nocase
        $s3 = "SysInfoCollect" ascii nocase
        $ua = "HavocClient" ascii
        $taskhost = "taskhostw.exe" ascii
        $json = "{ \"id\"" ascii

    condition:
        uint16(0) == 0x5A4D and 2 of ($s1, $s2, $s3, $ua, $taskhost, $json)
}