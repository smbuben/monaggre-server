#!/usr/bin/env python

#
# Copyright (C) 2014 Stephen M Buben <smbuben@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

import inspect
import optparse
import os
import sys
import unittest


def main(sdk_path, test_path):
    sys.path.insert(0, sdk_path)
    import dev_appserver
    dev_appserver.fix_sys_path()
    suite = unittest.loader.TestLoader().discover(test_path)
    unittest.TextTestRunner(verbosity=2).run(suite)


if __name__ == '__main__':
    usage = """
    %prog
    %prog sdk_path test_path

Run unit tests for AppEngine apps. With no arguments, assume project hiearchy:

    google_appengine/
        ... downloaded appengine sdk files ...
    project/
        ... project files ...
        test/
            ... tests ...
            run_tests.py <-- (this file)

Or, use arguments to customize:

    sdk_path    Path to the SDK installation.
    test_path   Path to the package containing test modules.
"""
    parser = optparse.OptionParser(usage)
    _, args = parser.parse_args()
    if len(args) == 0:
        test_path = os.path.dirname(os.path.abspath(inspect.stack()[0][1]))
        os.chdir(test_path)
        main('../../google_appengine', '.')
    elif len(args) == 2:
        main(args[0], args[1])
    else:
        parser.print_help()
        sys.exit(1)

