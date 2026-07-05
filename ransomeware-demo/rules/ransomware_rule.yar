rule Generic_Ransomware
{
    meta:
        description = "Generic ransomware detection"

    strings:
        $s1 = "decrypt your files"
        $s2 = "bitcoin"
        $s3 = "Your files have been encrypted"

    condition:
        2 of ($s*)
}

/* ---------- ADD MORE RULES BELOW ---------- */

rule WannaCry_Ransomware
{
    strings:
        $w1 = "WanaDecryptor"
        $w2 = "Please Read Me.txt"
        $w3 = "WANACRY"

    condition:
        2 of ($w*)
}

rule Locky_Ransomware
{
    strings:
        $l1 = ".locky"
        $l2 = "RSA-2048"
        $l3 = "Locky Recovery"

    condition:
        2 of ($l*)
}

rule Ryuk_Ransomware
{
    strings:
        $r1 = "RyukReadMe"
        $r2 = "vssadmin delete shadows"
        $r3 = "Wake up!"

    condition:
        2 of ($r*)
}