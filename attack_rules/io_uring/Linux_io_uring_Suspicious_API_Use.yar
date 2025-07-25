rule Linux_io_uring_Suspicious_API_Use
{
    meta:
        description = "Detects ELF binaries using io_uring syscalls suspiciously"
        author = "Cyber Graf"
        reference = "0xMatheuZ - io_uring EDR evasion"
        version = "1.0"
        license = "CC BY 4.0"
        threat_name = "EDR Evasion via io_uring"

    strings:
        $s1 = "io_uring_setup" ascii
        $s2 = "io_uring_register" ascii
        $s3 = "io_uring_enter" ascii
        $exec = {48 89 ?? ?? ?? ?? 00 00 E8 ?? ?? ?? ??} // вызов io_uring через RAX

    condition:
        uint32(0) == 0x464c457f and 2 of ($s*)
}