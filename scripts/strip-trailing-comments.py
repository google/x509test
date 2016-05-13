#!/usr/bin/env python
import sys
import re

just_comment = re.compile('^\s*#[^#]*$')
eol_comment = re.compile('^(?P<code>[^#]+?)\s*#.*$')
with open(sys.argv[1], "r") as infile:
    for line in infile:
        if just_comment.match(line):
            print line,
        else:
            m = eol_comment.match(line)
            if m:
                print m.group('code')
            else:
                print line,
