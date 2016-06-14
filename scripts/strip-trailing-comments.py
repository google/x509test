#!/usr/bin/env python
# Copyright 2016 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
