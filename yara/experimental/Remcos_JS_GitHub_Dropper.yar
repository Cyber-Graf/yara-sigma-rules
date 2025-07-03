rule Remcos_JS_GitHub_Dropper
{
    meta:
        description = "Detects JS dropper with GitHub delivery and PowerShell payload (Remcos)"
        author = "Cyber Graf"
        version = "1.0"
        license = "CC BY 4.0"
        reference = "ANY.RUN, June 2025"

    strings:
        $a1 = "raw.githubusercontent.com" ascii
        $a2 = "powershell -w hidden -nop -c" ascii
        $a3 = "function decodeBase64" ascii
        $a4 = "while(true)" ascii

    condition:
        all of ($a*)
}
