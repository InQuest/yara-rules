rule IQY_File
{
    meta:
        Author = "InQuest Labs"
        Reference = "https://www.inquest.net"
        Description = "Detects all Excel IQY files by identifying the WEB 'magic' on the first line and also includes any URL."
        Severity = "0"

   strings:
        /* match WEB on the first line of a file
           takes into account potential whitespace before or after case-insensitive "WEB" string
        */
        $web = /^[ \t]*WEB[ \t]*(\x0A|\x0D\x0A)/ nocase

        /* match any http or https URL within the file */
        $url = /https?:\/\/([\w\.-]+)([\/\w \.-]*)/

    condition:
        $web at 0 and $url
}
