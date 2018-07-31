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

Update July 2018:

    https://www.fireeye.com/blog/threat-research/2018/07/microsoft-office-vulnerabilities-used-to-distribute-felixroot-backdoor.html

The carrier in the FireEye report above utilizes the byte-nibble technique. Some additional hashes to play with from VT:

    first_seen,sha256
    2018-04-18 06:57:18,10ceb5916cd90e75f8789881af40287c655831c5086ae1575b327556b63cdb24
    2018-05-09 21:07:27,de1409ccd869153ab444de9740b1733e50f182beea5daea7a9b77e56bd354aa9
    2018-05-14 16:44:06,7532ef45138d57ac4ed9eeec0f62f9edef4447723efde66bffcff38175f6d62d
    2018-05-15 08:41:59,6e2a271f9e137bc8c62fa304ede3b5bac046f4957d3f8249dde60357463e651d
    2018-05-18 14:33:24,0655d58db2798ad8336f92dd580f988312f37f3e52b405c9c71d3afd2bd2c290
    2018-05-18 17:04:52,758a0e300edff045ede857ad4b01c4d51f373add59c43b78047dd69ce4c7765a
    2018-06-06 14:12:51,d78fac933ab239c12ce24244188e65dea150ddd183fd88417d9c311914af30c2
    2018-06-27 09:03:21,7a0c20c85f01a9d11e2b5f67483d154864b1a1dc8112566df156f8232d38a4d5
    2018-06-27 09:18:37,5484b0f37f21861c480f43c40168d9767bf619dfcd92436193ab7d7aee188fc4
    2018-06-27 11:50:56,96e8aae58cd3e4a39238372cb67a99441f78d6c92fd78c3c9ba16424b99ba3cf
    2018-06-27 12:06:09,48aa32a4490beefc488add66df46b75bbd480af9cedebaa0c096ac216dd08d79
    2018-06-27 12:21:21,0c91e70676609b765e4d20afa992660f306798af60f9c164dd41336590636864
    2018-07-06 11:53:40,e6c37c6d6ce40ca9ffd4b0ad63d1399f11949fc28a2cf66282daa54645f24b4c
    2018-07-11 03:47:27,45a86012cb99762d57d0fe1626d5cdc9046751e26eac7d9ef0e8adedb03b8661
    2018-07-18 01:33:45,54b32a37fc521c258da32fd15acb580d03b820ff69977696af5a134edea48f86
    2018-07-18 08:35:46,cd4de8bfd2ac80175f83c6f2f754c9c0f693dc081d16e5035c208ca384e01b02
    2018-07-19 01:09:45,884303b1f4fe64f7ac19f5fbea9afb72f6cd5cd069e195452e5c77cc07fefab9
    2018-07-20 01:38:19,62c03c4cd9d94029be4e38c4cbaf934a3a19919fab6ef3561a22f544bc892a2f
    2018-07-23 10:35:39,3f922fe437a4394c9c35dbf05252ff8fa20e2bbf10eb726ba9398c933c797837
    2018-07-27 09:26:52,008d54ba06ec1b5fd909c1e0e9d9ba9a23c6d9a11d6e0f6910877e639b31c529

For those of you without VT access, those samples are available in our malware-samples repository at:

    https://github.com/InQuest/malware-samples/tree/master/2018-08-RTF-Byte-Nibble-Obfuscation
*/

rule RTF_Byte_Nibble_Obfuscation_method1
{
    strings:
        $magic    = {7b 5c 72}
        $update   = "\\objupdate" nocase
        $data     = "\\objdata"   nocase
        $nibble_a = /([A-Fa-f0-9]\\'[A-Fa-f0-9]{4}){4}/
        $nibble_b = /(\\'[A-Fa-f0-9]+\\'[A-Fa-f0-9]{4}){4}/
    condition:
        $magic in (0..30) and all of them and (#nibble_a > 10 or #nibble_b > 10)
}

rule RTF_Byte_Nibble_Obfuscation_method2
{
    strings:
        $magic  = {7b 5c 72}
        $nibble = /\\objupdate.{0,1024}\\objdata.{0,1024}([A-Fa-f0-9]\\'[A-Fa-f0-9]{4}){2}/
    condition:
        $magic in (0..30) and all of them
}
