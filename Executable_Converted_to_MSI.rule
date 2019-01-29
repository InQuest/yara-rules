// see the relevant post at: http://blog.inquest.net/blog/2019/01/29/Carving-Sneaky-XLM-Files/
rule Executable_Converted_to_MSI
{
    strings:
        $magic = /^\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1\x00\x00\x00/
        $url   = "www.exetomsi.com" nocase
    condition:
        $magic at 0 and $url
}
