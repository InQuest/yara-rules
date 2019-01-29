// see the relevant post at: http://blog.inquest.net/blog/2019/01/29/Carving-Sneaky-XLM-Files/
rule MSIExec_Pivot
{
    strings:
        $serf19   = "serf=19" nocase ascii wide
        $msiserf1 = "msiexec" nocase ascii wide
        $msiserf2 = "serf="   nocase ascii wide
        $msiserf3 = "http"    nocase ascii wide
    condition:
        $serf19 or all of ($msiserf*)
}
