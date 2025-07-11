rule BERT_Ransomware_ConfigStrings
{
    meta:
        description = "Detects embedded config or logic markers in BERT ransomware"
        author = "Cyber Graf"
        license = "CC BY 4.0"

    strings:
        $s1 = "Encrypting files..." ascii
        $s2 = "BERT_LOG_START" ascii
        $s3 = "SYSTEM_ROOT_BACKUP" ascii
        $ext = ".bert" ascii

    condition:
        2 of ($s*)
}
