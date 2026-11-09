// Kshatriya built-in rules.
// Only harmless test content and project-authored rules belong here. Third-party rule sets must pass
// the licence review in docs/adr/0003-dependency-licensing.md before they are bundled.
//
// Metadata understood by Kshatriya:
//   name        detection name (A-Z a-z 0-9 . _ - / :), default "<namespace>.<rule>"
//   category    malware | pua | suspicious | test   (default: suspicious)
//   confidence  low | medium | high                 (default: medium)
//   description free text shown to the user

rule Kshatriya_Test_EICAR
{
    meta:
        name = "Kshatriya.Test.EICAR.Yara"
        category = "test"
        confidence = "high"
        description = "EICAR anti-malware test file (harmless)."
    strings:
        // The test string is split in two so that this rule file is not itself an EICAR file.
        $head = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
        $tail = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $head at 0 and $tail at 28 and filesize <= 128
}
