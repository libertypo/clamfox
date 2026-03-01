rule Wicar_EICAR_Test {
    meta:
        description = "Wicar EICAR test file or exploit simulation"
        author = "ClamFox"
        reference = "http://wicar.org"
    strings:
        $s1 = "wicar.org/data/ms14"
        $s2 = "wicar.org/data/eicar"
        $s3 = "alert(\"WICAR"
        $s4 = "malware.wicar.org"
        $s5 = "runaaaa"
        $s6 = "Shell.Application"
    condition:
        $s1 or $s2 or $s3 or $s4 or ($s5 and $s6)
}
