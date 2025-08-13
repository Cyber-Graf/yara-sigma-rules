rule PaperWerewolf_RAR_payload_docs
{
    meta:
        description = "Detects decoy documents from malicious RAR archives used in Paper Werewolf campaigns"
        author = "Cyber Graf"
        reference = "BI.ZONE — Paper Werewolf атакует Россию с использованием уязвимости нулевого дня в WinRAR"
        version = "1.0"
        license = "CC BY 4.0"
        threat_name = "Paper Werewolf / GOFFEE"

    strings:
        $doc1 = "minprom_04072025.rar" nocase
        $doc2 = "Министерство" wide ascii
        $doc3 = "НИИ" wide ascii
        $doc4 = "Start Menu\\Programs\\Startup" nocase

    condition:
        any of ($doc*)
}