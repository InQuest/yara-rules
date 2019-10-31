rule Symbolic_Link_Files_Macros_File_Characteristic
{

	meta:
		Author = "InQuest Labs"
		URL         = "https://github.com/InQuest/yara-rules/edit/master/Symbolic_Link_Files_Macros_File_Characteristic.rule"
		Description = "This signature detects Symbolic Link (SLK) files that contain Excel 4.0 macros. While not inherently malicious, these SLK files can be used used by attackers to evade detection and deliver malicious payloads."
		References = "https://outflank.nl/blog/2019/10/30/abusing-the-sylk-file-format/"

	strings:
			$magic = "ID;P"
	
	$re1 = /\x0aO;E[\r\n]/ nocase
	/*The first line with the ID and P records is a marker that indicates this file is a SYLK file.
The second line with the O record sets options for this document. E marks that it is a macro-enabled document.
	*/
	
	//If we want to be extra cautious then we can enable $re2 
	//$re2 = /\x0aNN;NAuto_open;/ nocase
	//third line is a names record NN. We set the name Auto_open for the cell at row 1, column 1 (ER1C1).
	
	/*
	Sample:
	
	ID;P
	O;E
	NN;NAuto_open;ER1C1;KOutFlank;F
	C;Y1;X1;N;EDIRECTORY()
	C;X1;Y2;K0;ESELECT(R1C1)
	C;X1;Y2;N;K13;EFIND(":";;R1C1)
	C;X1;Y3;N;K19;EFIND(":";;R1C1;;R2C1+1)
	C;X1;Y4;N;K27;EFIND(":";;R1C1;;R3C1+1)
	C;X1;Y5;N;ELEFT(R1C1;;R4C1 -1)
	C;X1;Y6;N;KFALSE;EDIRECTORY(R[-1]C)
	C;X1;Y7;N;K0;EFOPEN("MALICIOUS.FILE";;3)
	C;X1;Y9;K0;EFWRITE(R7C1;;"PWNED BY OUTFLANK")
	C;X1;Y10;K0;EFCLOSE(R7C1)
	C;X1;Y11;K0;EHALT()
	E
	
	*/
	condition:
			$magic in (0..100) and all of ($re*)
}
