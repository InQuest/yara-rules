/*
This signature is mostly public sourced and detects an in-the-wild exploit for CVE-2018-4878. Following the
conversation at:

    http://blog.inquest.net/blog/2018/02/07/cve-2018-4878-adobe-flash-0day-itw
    https://twitter.com/i/moments/960633253165191170

 InQuest customers can detect related events on their network by searching for:
 
    event ID 5000798
*/

rule CVE_2018_4878_0day_ITW
{
    strings:   
        $known1 = "F:\\work\\flash\\obfuscation\\loadswf\\src" nocase wide ascii   
        $known2 = "G:\\FlashDeveloping" nocase wide ascii   
        $known3 = "Z:\\Main\\zero day\\Troy" nocase wide ascii   
        $known4 = "C:\\Users\\Rose\\Adobe Flash Builder 4.6\\ExpAll\\src" nocase wide ascii   
        $known5 = "F:\\work\\flash\\obfuscation\\loadswf\\src" nocase wide ascii   
        $known6 = "admincenter/files/boad/4/manager.php" nocase wide ascii

        // EMBEDDED FLASH OBJECT BIN HEADER   
        $header = "rdf:RDF" wide ascii   
    
        // OBJECT APPLICATION TYPE TITLE
        // disabled 2/13/18 due to false positive on 2a75ff1acdf9141bfb836343f94f4a73b8c64b226b0e2ae30a69e9aacc472cba
        // $title = "Adobe Flex" wide ascii   
    
        // PDB PATH    
        $pdb = "F:\\work\\flash\\obfuscation\\loadswf\\src" wide ascii   
    
        // LOADER STRINGS   
        $loader1 = "URLRequest" wide ascii   
        $loader2 = "URLLoader" wide ascii   
        $loader3 = "loadswf" wide ascii   
        $loader4 = "myUrlReqest" wide ascii   
      
        // 1a3269253784f76e3480e4b3de312dfee878f99045ccfd2231acb5ba57d8ed0d.fws exploit specific multivar definition.
        $observed_multivar_1 = /999(\x05[a-z]10[0-9][0-9]){100}/ nocase wide ascii
        $observed_multivar_2 = /999(\x05[a-z]11[0-9][0-9]){100}/ nocase wide ascii
        $flash_magic         = { (43 | 46 | 5A) 57 53 }

        // 53fa83d02cc60765a75abd0921f5084c03e0b7521a61c4260176e68b6a402834 exploit specific.
        $exp53_1 = "C:\\Users\\Miha\\AdobeMinePoC"
        $exp53_2 = "UAFGenerator"
        $exp53_3 = "shellcodBytes"
        $exp53_4 = "DRM_obj"
        $exp53_5 = "MainExp"

    condition:
        ($flash_magic at 0 and all of ($observed_multivar*))
            or
        (any of ($known*))
            or
        // disabled 2/13/18 due to false positive on 2a75ff1acdf9141bfb836343f94f4a73b8c64b226b0e2ae30a69e9aacc472cba
        //(all of ($header*) and all of ($title*) and 3 of ($loader*))
        //    or
        (all of ($pdb*) and all of ($header*) and 1 of ($loader*))
            or
        ($flash_magic at 0 and all of ($exp53*))
}
