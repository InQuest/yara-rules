rule SC_Microsoft_Excel_Data_Connection
{
    meta:
        Author      = "InQuest Labs"
        URL         = "https://github.com/InQuest/yara-rules"
        Description = "https://inquest.net/blog/2020/03/18/Getting-Sneakier-Hidden-Sheets-Data-Connections-and-XLM-Macros"
    strings:
        $magic = { D0 CF 11 E0 A1 B1 1A E1 00 00 00 }
        $url = /https?:\/\/[\w\/\.\-]+/ nocase ascii wide
        // 0x876 = DCONN then we want to ensure that the records fBackgroundQuery flag (bit) is raised.
        $dconn = /\x76\x08\x00\x00\x04\x00[\x40-\x7f\xc0-\xff]/
    condition:
        $magic in (0..1024) and $dconn and $url
}
