/*

This signature is designed to detect the obfuscation method described by Boris Larin here:

    Disappearing bytes: Reverse engineering the MS Office RTF parser
    https://securelist.com/disappearing-bytes/84017/
    February 21st 2018

An excellent write-up and highly recommended read. In essence, by reverse engineering the RTF
parsing state machine, he was able to find a character sequence that would result in what we
like to call a "byte nibble".

This technique was interesting when we first saw it back in February, it's even more interesting
today however in light of the patching of the following in-the-wild exploited 0day:

    CVE-2018-8174: Microsoft VBScript Use-After-Free (aka Double Kill)

The vulnerability affected Internet Explorer / VBScript and was originally discovered by Qihoo
security researchers who noticed the 0day in the wild on April 20th. They dubbed it "Double Kill"
but kept specifics under wrap. Microsoft released a patch on May 8th.

An initial public report, from the Qihoo 360 Security team:

    https://weibo.com/ttarticle/p/show?id=2309404230886689265523

A very well done and complete dissection from the researchers at Kaspersky (kudos to Boris again!):

    https://securelist.com/root-cause-analysis-of-cve-2018-8174/85486/

Note that the 0day was exploited via a second stage payload triggered with the opening of a
malicious RTF document. That document, originally uploaded to VirusTotal on April 18, leverages
the disappearing bytes technique detailed earlier:

    https://www.virustotal.com/en/file/10ceb5916cd90e75f8789881af40287c655831c5086ae1575b327556b63cdb24/analysis

We'll continue to earmark interesting tidbits around the subject matter here:

    https://twitter.com/i/moments/994122868949770240

We have two versions of this rule for your hunting pleasure. It's worth mentioning that searching
through our past few months of harvested RTF samples ... only the 0day sample in question triggered
an alert. Certainly, the usage of this obfuscation technique will ramp up.
*/

rule RTF_Byte_Nibble_Obfuscation_method1
{
    strings:
        $magic  = {7b 5c 72}
        $update = "\\objupdate" nocase
        $data   = "\\objdata"   nocase
        $nibble = /([A-Fa-f0-9]\\'[A-Fa-f0-9]{4}){4}/
    condition:
        $magic in (0..30) and all of them and #nibble > 10
}

rule RTF_Byte_Nibble_Obfuscation_method2
{
    strings:
        $magic  = {7b 5c 72}
        $nibble = /\\objupdate.{0,1024}\\objdata.{0,1024}([A-Fa-f0-9]\\'[A-Fa-f0-9]{4}){2}/
    condition:
        $magic in (0..30) and all of them
}
