rule Microsoft_XLSX_with_Macrosheet
{
    meta:
        Author      = "InQuest Labs"
        URL         = "https://inquest.net/blog/2020/05/06/ZLoader-4.0-Macrosheets-Evolution"
        Description = "Basic hunt rule for XLS* with macrosheets." 

    strings:
        $magic_xlsx  = /^\x50\x4B\x03\x04/
        $anchor_xlsx = /xl\/macrosheets\/[a-zA-Z0-9_-]+\.xmlPK/

    condition:
        $magic_xlsx at 0 and $anchor_xlsx
}
