/*
Generically detect exploitation of CVE-2018-4878, a use-after-free vulnerability affecting Adobe Flash versions up to
and including 28.0.0.137. Following the conversation at:

    http://blog.inquest.net/blog/2018/02/07/cve-2018-4878-adobe-flash-0day-itw
    https://twitter.com/i/moments/960633253165191170

 InQuest customers can detect related events on their network by searching for:
 
    event ID 5000805
*/

rule Adobe_Flash_DRM_Use_After_Free
{    
    meta:
        note  = "This YARA rule is intended to run atop of decompiled Flash."

    strings:
        $as   = "package"
        $exp1 = "import com.adobe.tvsdk.mediacore" 	// covers .*
        $exp2 = "createDispatcher("
        $exp3 = "createMediaPlayer("
        $exp4 = "drmManager.initialize("    		// com.adobe.tvsdk.mediacore.DRMOperationCompleteListener;
        $vara_1 = "push(this)"
        $vara_2 = "push(null)"
        $vara_3 = /pop\(\)\..+\s*=\s*.+pop\(\)/
        $varb_1 = /push\([^\)]{1,24}drmManager.initialize/

        // all the requisite pieces in a single function.
        $varc_1 = /\{[^\}]+createDispatcher\s*\([^\}]+createMediaPlayer\s*\([^\}]+drmManager\.initialize\s*\([^\}]+=\s*null[^\}]+\}/

    condition:
        $as at 0 and all of ($exp*) and (all of ($vara*) or $varb_1 or $varc_1)
}
