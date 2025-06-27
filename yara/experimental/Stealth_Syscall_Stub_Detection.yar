rule Stealth_Syscall_Stub_Detection
{
    meta:
        description = "Detects raw syscall stub: mov r10, rcx; mov eax, XX; syscall [; ret|jmp]"
        author = "Cyber Graf"
        reference = "Stealth Syscall Execution - bypassing ETW/EDR"
        threat_name = "Stealth Syscall Technique"
        license = "CC BY 4.0"

    strings:
        $stub1 = { 4C 8B D1 B8 ?? ?? ?? ?? 0F 05 (C3 | E9 ?? ?? ?? ??)? }

    condition:
        $stub1 and filesize < 1MB
}