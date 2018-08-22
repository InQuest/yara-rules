rule IQY_File_With_Pivot_Extension_URL
{
    meta:
        Author = "InQuest Labs"
        Reference = "https://www.inquest.net"
        Description = "Detect Excel IQY files with URLs that contain commonly used malicious file extensions that may act as a pivot to a secondary stage."
        Severity = "9"
    strings:
        /*
           match WEB on the first line of a file
           takes into account potential whitespace before or after case-insensitive "WEB" string
        */
         $web = /^[ \t]*WEB[ \t]*(\x0A|\x0D\x0A)/ nocase

        /*
            generic URL to direct download a file containing a potentially malicious extension.
            File extensions were decided based upon common extensions seen in the wild
            The extension list can be expanded upon as new information comes available from matches
            on the Stage 1 or Stage 2 signatures
         */

        $url = /https?:\/\/[\w\.\/]+\.(scr|exe|hta|vbs|ps1|bat|dat|rar|zip|ace)/ nocase

    condition:
        $web at 0 and $url
}
