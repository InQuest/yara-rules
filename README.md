# yara-rules
A collection of YARA rules we wish to share with the world. These rules should not be considered production appropriate. Rather, they are valuable for research and hunting purposes. The rules are listed here, alphabetically, along with references for further reading:

* CVE-2018-4878: Adobe Flash MediaPlayer DRM user-after-free Vulnerability
  * [CVE_2018_4878_0day_ITW](https://github.com/InQuest/yara-rules/blob/master/CVE_2018_4878_0day_ITW.rule)
  * [Microsoft_Office_Document_with_Embedded_Flash_File](https://github.com/InQuest/yara-rules/blob/master/Microsoft_Office_Document_with_Embedded_Flash_File.rule)
  * [Adobe_Flash_DRM_Use_After_Free](https://github.com/InQuest/yara-rules/blob/master/Adobe_Flash_DRM_Use_After_Free.rule)
  * [Blog: Adobe Flash MediaPlayer DRM Use-after-free Vulnerability](http://blog.inquest.net/blog/2018/02/07/cve-2018-4878-adobe-flash-0day-itw)
  * Follow highlights of the conversation on Twitter from this ["moment" we maintain](https://twitter.com/i/moments/960633253165191170).
* [Embedded PE Files](https://github.com/InQuest/yara-rules/blob/master/Embedded_PE.rule)
  * Discover embedded PE files, without relying on easily stripped/modified header strings.
* [Executables Converted to MSI](https://github.com/InQuest/yara-rules/blob/master/Executable_Converted_to_MSI.rule)
  * [Blog: "Carving Sneaky XLM Files"](http://blog.inquest.net/blog/2019/01/29/Carving-Sneaky-XLM-Files/)
  * [www.exetomsi.com](http://www.exetomsi.com)
* [Hidden Bee Custom Windows Executable Format](https://github.com/InQuest/yara-rules/blob/master/Hidden_Bee_Elements.rule)
  * [Malwarebytes Blog](https://blog.malwarebytes.com/threat-analysis/2018/08/reversing-malware-in-a-custom-format-hidden-bee-elements/)
  * [Malware Samples](https://github.com/InQuest/malware-samples/tree/master/2018-08-Hidden-Bee-Elements)
* [Hunting Suspicious IQY Files](http://blog.inquest.net/blog/2018/08/23/hunting-iqy-files-with-yara/)
  * [IQY_File](https://github.com/InQuest/yara-rules/blob/master/IQY_File.rule)
  * [IQY_File_With_Suspicious_URL](https://github.com/InQuest/yara-rules/blob/master/IQY_File_With_Suspicious_URL.rule)
  * [IQY_File_With_Pivot_Extension_URL.rule](https://github.com/InQuest/yara-rules/blob/master/IQY_File_With_Pivot_Extension_URL.rule)
* [Microsoft Excel Hidden Macro Sheets](https://github.com/InQuest/yara-rules/blob/master/Excel_Hidden_Macro_Sheet.rule)
  * [Blog: "Carving Sneaky XLM Files"](http://blog.inquest.net/blog/2019/01/29/Carving-Sneaky-XLM-Files/)
* [Microsoft_Office_DDE_Command_Execution](https://github.com/InQuest/yara-rules/blob/master/Microsoft_Office_DDE_Command_Execution.rule)
  * Blogs: [Overview, Hunting, and Mitigation](http://blog.inquest.net/blog/2017/10/13/microsoft-office-dde-macro-less-command-execution-vulnerability/), [Freddie Mac Targeted Lure](http://blog.inquest.net/blog/2017/10/14/02-microsoft-office-dde-freddie-mac-targeted-lure/), [SEC OMB Masquerading Lure](http://blog.inquest.net/blog/2017/10/14/01-microsoft-office-dde-sec-omb-approval-lure/), [Vortex Ransomware Targeting Poland](http://blog.inquest.net/blog/2017/10/14/03-microsoft-office-dde-poland-ransomware/).
  * Follow highlights of the conversation on Twitter from this ["moment" we maintain](https://twitter.com/i/moments/918126999738175489).
* [MSIExec Pivot](https://github.com/InQuest/yara-rules/blob/master/MSIExec_Pivot.rule)
  * [Blog: "Carving Sneaky XLM Files"](http://blog.inquest.net/blog/2019/01/29/Carving-Sneaky-XLM-Files/)
  * [Reference: Custom Action Type 19](https://docs.microsoft.com/en-us/windows/desktop/msi/custom-action-type-19)
* [NTLM_Credentials_Theft_via_PDF](https://github.com/InQuest/yara-rules/blob/master/NTLM_Credentials_Theft_via_PDF_Files.rule)
  * This signature detects Adobe PDF files that reference a remote UNC object for the purpose of leaking NTLM hashes.
New methods for NTLM hash leaks are discovered from time to time. This particular one is triggered upon opening of a
malicious crafted PDF. Original write-up from [CheckPoint](https://research.checkpoint.com/ntlm-credentials-theft-via-pdf-files/).
* [RTF_Byte_Nibble_Obfuscation](https://github.com/InQuest/yara-rules/blob/master/RTF_Byte_Nibble_Obfuscation.rule)
  * This signature is designed to detect the obfuscation method described by Boris Larin here [Disappearing bytes: Reverse engineering the MS Office RTF parser](https://securelist.com/disappearing-bytes/84017/). This obfuscation method is rarely seen but was used in the distribution of CVE-2018-8174 0day discovered in-the-wild.
  * We'll continue to earmark interesting tidbits around the subject matter in this [Twitter Moment](https://twitter.com/i/moments/994122868949770240).
