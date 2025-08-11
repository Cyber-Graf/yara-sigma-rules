rule BERT_Ransomware_GoPE
{
    meta:
        description = "Detects BERT ransomware written in Go with specific strings"
        author = "Cyber Graf"
        license = "CC BY 4.0"
        reference = "Trend Micro, July 2025"

    strings:
        $go1 = "crypto/aes" ascii
        $go2 = "os.OpenFile" ascii
        $mark = "BERT Encrypted" ascii
        $ext = ".bert" ascii
        $bat = ".bat" ascii

    condition:
        uint16(0) == 0x5A4D and 3 of ($*)
}
