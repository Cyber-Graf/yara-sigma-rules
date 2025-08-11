rule NyashTeam_VPN_AutoDeploy
{
    meta:
        description = "Detects shell scripts used by NyashTeam to auto-deploy VPN/proxy infrastructure"
        author = "Cyber Graf"
        version = "1.0"
        license = "CC BY 4.0"

    strings:
        $s1 = "openvpn-install.sh" ascii
        $s2 = "iptables -t nat -A POSTROUTING" ascii
        $s3 = "ufw allow" ascii
        $s4 = "curl -O https://raw.githubusercontent.com/NyashTeam/" ascii

    condition:
        all of ($s*)
}