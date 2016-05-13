#!/usr/bin/env python
# Copyright 2015-2016 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Python 2.x/3.x compatibility utilities.

This module defines a collection of functions that allow the same Python
source code to be used in both Python 2.x and Python 3.x.

 - prnt() prints its arguments to a file, with given separator and ending.
 - to_long() creates a (long) integer object from its input parameter.
 - u() allows string literals involving non-ASCII characters to be
   used in both Python 2.x / 3.x, e.g. u("\u0101 is a-with-macron")
 - uchr() generates a single character Unicode string whose point code
   is the given (integer) argument, e.g. uchr(257).
"""
import sys


if sys.version_info >= (3, 0):  # pragma no cover
    import builtins
    print3 = builtins.__dict__['print']

    unicod = str
    to_long = int

    def prnt(*args, **kwargs):
        sep = kwargs.get('sep', ' ')
        end = kwargs.get('end', '\n')
        file = kwargs.get('file', None)
        print3(*args, **{'sep': sep, 'end': end, 'file': file})

    class UnicodeMixin(object):
        """Mixin class to define a __str__ method in terms of __unicode__ method"""
        __str__ = lambda x: x.__unicode__()

else:  # pragma no cover
    unicod = unicode

    def prnt(*args, **kwargs):
        sep = kwargs.get('sep', ' ')
        end = kwargs.get('end', '\n')
        file = kwargs.get('file', None)
        if file is None:
            file = sys.stdout
        print >> file, sep.join([str(arg) for arg in args]) + end,

    class UnicodeMixin(object):  # pragma no cover
        """Mixin class to define a __str__ method in terms of __unicode__ method"""
        __str__ = lambda x: unicode(x).encode('utf-8')
