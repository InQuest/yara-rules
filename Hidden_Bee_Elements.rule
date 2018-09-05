rule Hidden_Bee_Elements
{
    meta:
        Author      = "InQuest Labs"
        Reference   = "https://blog.malwarebytes.com/threat-analysis/2018/08/reversing-malware-in-a-custom-format-hidden-bee-elements/"
        Description = "This signature detects a custom Windows executable format used in relation to Hidden Bee and Underminer exploit kit."

    strings:
        /*
            sample payloads:
                https://www.virustotal.com/#/file/76b70f1dfd64958fca7ab3e18fffe6d551474c2b25aaa9515181dec6ae112895/details
                download: https://github.com/InQuest/malware-samples/blob/master/2018-08-Hidden-Bee-Elements/11310b509f8bf86daa5577758e9d1eb5

                https://www.virustotal.com/#/file/c1a6df241239359731c671203925a8265cf82a0c8c20c94d57a6a1ed09dec289/details
                download: https://github.com/InQuest/malware-samples/blob/master/2018-08-Hidden-Bee-Elements/b3eb576e02849218867caefaa0412ccd

             $ yara Hidden_Bee_Elements.rule -wr ../malware-samples/2018-08-Hidden-Bee-Elements/
                 Hidden_Bee_Elements ../malware-samples/2018-08-Hidden-Bee-Elements//b3eb576e02849218867caefaa0412ccd
                 Hidden_Bee_Elements ../malware-samples/2018-08-Hidden-Bee-Elements//11310b509f8bf86daa5577758e9d1eb5

            IDA loader module creation write-up and source from @RolfRolles:
                http://www.msreverseengineering.com/blog/2018/9/2/weekend-project-a-custom-ida-loader-module-for-the-hidden-bee-malware-family
                https://github.com/RolfRolles/HiddenBeeLoader

            Binary file format struct from @hasherezade:
                typedef struct {
                    DWORD magic;

                    WORD dll_list;
                    WORD iat;
                    DWORD ep;
                    DWORD mod_size;

                    DWORD relocs_size;
                    DWORD relocs;
                } t_bee_hdr;
        */

        $magic = { 01 03 00 10 }
        $dll   = /(ntdll|kernel32|advapi32|cabinet|msvcrt|ws2_32|phlpape)\.dll/ nocase ascii wide fullword
        
        // case-insensitive base64 http:// or https:// URI prefix
        // algorithm behind this generation magic: http://www.erlang-factory.com/upload/presentations/225/ErlangFactorySFBay2010-RobKing.pdf
        $b64_uri = /([\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx][Io][Vd][FH][R][Qw][O]i\x38v[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx][Io][Vd][FH][R][Qw][Uc][z]ovL[\x2b\x2f-\x39w-z]|[\x2b\x2f-\x39A-Za-z][\x30\x32EGUWkm][h][\x30U][Vd][FH][A]\x36Ly[\x2b\x2f\x38-\x39]|[\x2b\x2f-\x39A-Za-z][\x30\x32EGUWkm][h][\x30U][Vd][FH][B][Tz][O]i\x38v[\x2b\x2f-\x39A-Za-z]|[Sa][FH][R][\x30U][Uc][D]ovL[\x2b\x2f-\x39w-z]|[Sa][FH][R][\x30U][Uc][FH][M]\x36Ly[\x2b\x2f\x38-\x39])/

    condition:
        $magic at 0
            and
        (
            // at least 3 known DLL imports in the first 128 bytes.
            for all i in (1..3) : (@dll[i] < 128)

                or

            // base64 encoded URLs.
            $b64_uri
        )
}
