#!/usr/bin/env python
import re
import sys
YARA_TEMPLATE = """
    rule {rule_name}
    {{
        strings:
        {string_defs}
        condition:
            any of them
    }}
"""
if len(sys.argv) != 3:
    sys.exit("usage: %s RULE_NAME INPUT" % sys.argv[0])
strings = []
with open(sys.argv[2], "r") as fp:
    for number, line in enumerate(fp):
        strings.append("$s%d = /%s/" % (number, re.escape(line.strip())))
print(YARA_TEMPLATE.format(rule_name=sys.argv[1], string_defs="\n\t".join(strings)))
