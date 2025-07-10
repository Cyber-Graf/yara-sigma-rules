rule Rubeus_DiamondTicket_OPSEC
{
    meta:
        description = "Detects command-line artifacts of Rubeus Diamond Ticket with /opsec flag"
        author = "Cyber Graf"
        version = "1.0"
        reference = "Huntress, 2025"
        license = "CC BY 4.0"
        threat_name = "Diamond Ticket Attack"

    strings:
        $cmd1 = "Rubeus.exe diamond" ascii
        $cmd2 = "/krbkey:" ascii
        $cmd3 = "/opsec" ascii
        $cmd4 = "/ticketuser:" ascii
        $cmd5 = "/nowrap" ascii

    condition:
        3 of ($cmd*)
}