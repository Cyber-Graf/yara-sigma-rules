rule FreeIPA_Kerberos_Roasting_Script
{
    meta:
        description = "Detects Kerberos AS-REQ roasting (CVE-2024-3183)"
        author = "Cyber Graf"
        version = "1.0"
        license = "CC BY 4.0"
        threat_name = "Kerberos Roasting Toolkit"

    strings:
        $s1 = "AS-REQ" ascii
        $s2 = "PREAUTH_FAILED" ascii
        $s3 = "krbtgt@" ascii
        $s4 = "NoPreAuth" ascii
        $s5 = "user_list.txt" ascii
        $cmd1 = "kinit" ascii
        $cmd2 = "kvno" ascii

    condition:
        any of ($s*) and any of ($cmd*)
}