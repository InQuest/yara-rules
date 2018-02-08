/*
Detect Microsoft Office documents with embedded Adobe Flash files. Following the conversation at:

    http://blog.inquest.net/blog/2018/02/07/cve-2018-4878-adobe-flash-0day-itw
    https://twitter.com/i/moments/960633253165191170

 InQuest customers can detect related events on their network by searching for:
 
    event ID 3000032
*/

rule Microsoft_Office_Document_with_Embedded_Flash_File
{
    strings:
        $a = { 6e db 7c d2 6d ae cf 11 96 b8 44 45 53 54 00 00 }
        $b = { 57 53 }
    condition:
        $a and $b
}
