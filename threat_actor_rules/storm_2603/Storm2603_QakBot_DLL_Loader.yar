rule Storm2603_QakBot_DLL_Loader
{
    meta:
        description = "Detects DLLs used by Storm-2603 to load QakBot or Meterpreter payloads"
        author = "Cyber Graf"
        reference = "Check Point Research - Storm-2603’s Previous Ransomware Operations"
        version = "1.0"
        license = "CC BY 4.0"
        threat_name = "Storm-2603"

    strings:
        $s1 = "rundll32.exe C:\\Users\\admin\\AppData\\Local\\Temp\\tmp0.dll,Control_RunDLL" nocase
        $s2 = "Control_RunDLL" nocase
        $s3 = "svchost.exe" nocase

    condition:
        any of them
}
