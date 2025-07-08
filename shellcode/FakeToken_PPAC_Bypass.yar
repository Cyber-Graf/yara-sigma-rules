rule FakeToken_PPAC_Bypass
{
    meta:
        description = "Detects shellcode or PE attempting token spoofing for PPAC bypass"
        author = "Cyber Graf"
        reference = "SpecterOps - Administrator Protection"
        version = "1.1"
        license = "CC BY 4.0"

    strings:
        $token1 = { 4D 8B C4 48 8B 80 ?? ?? 00 00 }       // mov r8, gs:[KTHREAD]
        $token2 = { 48 8B 89 ?? ?? ?? ?? 48 89 4D ?? }    // mov rcx, [rcx+TOKEN]; mov [rbp+XX], rcx
        $ntsetinfo = "NtSetInformationProcess" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and 1 of ($token*) and $ntsetinfo
}