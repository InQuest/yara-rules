rule Hex_Encoded_Powershell
{
    meta:
        Author    = "InQuest Labs"
        Reference = "https://twitter.com/InQuest/status/1200125251675398149"
        Sample    = "https://labs.inquest.net/dfi/sha256/c430b2b2885804a638fc8d850b1aaca9eb0a981c7f5f9e467e44478e6bc961ee"
        Similar   = "https://labs.inquest.net/dfi/search/ext/ext_context/67697468756275736572636F6E74656E742E636F6D2F6A6F686E646F657465"

    strings:
        // http or https, powershell, invoke-webrequest
        // generated via: https://labs.inquest.net/tools/yara/iq-mixed-case
        $http = /[46]8[57]4[57]4[57]0([57]3)?3a2f2f/ nocase
        $powershell = /[57]0[46]f[57]7[46]5[57]2[57]3[46]8[46]5[46]c[46]c/ nocase
        $invoke = /[46]9[46]e[57]6[46]f[46]b[46]52d[57]7[46]5[46]2[57]2[46]5[57]1[57]5[46]5[57]3[57]4/ nocase

    condition:
        all of them
}
