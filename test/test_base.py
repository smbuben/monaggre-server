#
# This file is part of the Monaggre project.
#
# Copyright (C) 2014 Stephen M Buben <smbuben@gmail.com>
#
# Monaggre is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Monaggre is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with Monaggre.  If not, see <http://www.gnu.org/licenses/>.
#

import unittest
from google.appengine.api import users
from google.appengine.api import memcache
from google.appengine.ext import ndb
from google.appengine.ext import testbed
import os


class TestBase(unittest.TestCase):

    def setUp(self):
        self.testbed = testbed.Testbed()
        self.testbed.activate()
        self.testbed.init_user_stub()
        self.testbed.init_datastore_v3_stub()
        self.testbed.init_memcache_stub()
        self.testbed.init_taskqueue_stub()
        self.testbed.init_xmpp_stub()
        self.testbed.init_mail_stub()
        self.taskqueue = self.testbed.get_stub(testbed.TASKQUEUE_SERVICE_NAME)
        self.mail = self.testbed.get_stub(testbed.MAIL_SERVICE_NAME)
        self.set_default_user()

    def tearDown(self):
        self.testbed.deactivate()

    def set_user(self, email, user_id, is_admin=False):
        os.environ['USER_EMAIL'] = email
        os.environ['USER_ID'] = user_id
        os.environ['USER_IS_ADMIN'] = '1' if is_admin else '0'

    def set_default_user(self):
        self.set_user('testuser1@gmail.com', '1')

    def set_nonpermitted_user(self):
        self.set_user('nonpermitted1@gmail.com', '9999')

    def make_current_user_admin(self, is_admin):
        os.environ['USER_IS_ADMIN'] = '1' if is_admin else '0'

