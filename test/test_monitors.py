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
import test_base
from google.appengine.api import users
from google.appengine.api import memcache
from google.appengine.ext import ndb
from google.appengine.ext import testbed
from Crypto.PublicKey import RSA
import hashlib
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import models


class TestMonitors(test_base.TestBase):

    def setUp(self, *args, **kwargs):
        super(TestMonitors, self).setUp(*args, **kwargs)
        self.cases = list()

    def create_monitor(self, label, **kwargs):
        # XMPP and email enabling is for admins only.
        # Test those through special cases, not the default.
        enable_xmpp = kwargs.get('enable_xmpp', None)
        if enable_xmpp is None:
            enable_xmpp = False
        enable_email = kwargs.get('enable_email', None)
        if enable_email is None:
            enable_email = False
        case = [label, enable_xmpp, enable_email]
        urlsafe_key = models.Monitor.create(*case)
        case = [urlsafe_key, users.get_current_user()] + case + [False]
        self.cases.append(case)
        return case

    def replace_case(self, case, new_case):
        idx = self.cases.index(case)
        self.cases.pop(idx)
        self.cases.insert(idx, new_case)

    def update_monitor(self, case, label, **kwargs):
        # XMPP and email enabling is for admins only.
        # Test those through special cases, not the default.
        enable_xmpp = kwargs.get('enable_xmpp', None)
        if enable_xmpp is None:
            enable_xmpp = False
        enable_email = kwargs.get('enable_email', None)
        if enable_email is None:
            enable_email = False
        new_case = [label, enable_xmpp, enable_email]
        models.Monitor.update(case[0], *new_case)
        new_case = case[:2] + new_case + [case[5]]
        self.replace_case(case, new_case)
        return new_case

    def lock_monitor(self, case, new_status):
        models.Monitor.lock(case[0], new_status)
        new_case = case[0:5] + [new_status]
        self.replace_case(case, new_case)
        return new_case

    def delete_monitor_raw(self, case):
        ndb.Key(urlsafe=case[0]).delete()
        self.cases.remove(case)

    def delete_monitor(self, case):
        models.Monitor.delete(case[0])
        self.cases.remove(case)

    def __do_validate(self, monitor, case):
        urlsafe_key, owner, label, enable_xmpp, enable_email, locked = case
        self.assertEqual(monitor.key.urlsafe(), urlsafe_key)
        self.assertEqual(monitor.owner, owner)
        self.assertEqual(monitor.label, label)
        rsa1 = RSA.importKey(monitor.public_key)
        self.assertEqual(monitor.public_key, rsa1.publickey().exportKey())
        rsa2 = RSA.importKey(monitor.private_key)
        self.assertEqual(monitor.private_key, rsa2.exportKey())
        cipher_text = rsa1.encrypt('test', '')
        self.assertEqual('test', rsa2.decrypt(cipher_text))
        sha1 = hashlib.sha1()
        sha1.update(owner.email())
        sha1.update(rsa1.publickey().exportKey())
        self.assertEqual(monitor.monitor_id, sha1.hexdigest())
        self.assertEqual(monitor.enable_xmpp, enable_xmpp)
        self.assertEqual(monitor.enable_email, enable_email)

    def validate_all_monitors(self, monitors=None):
        if monitors is None:
            monitors = models.Monitor.query().fetch()
        self.assertEqual(len(self.cases), len(monitors))
        for monitor, case in zip(monitors, self.cases):
            self.__do_validate(monitor, case)

    def validate_monitor(self, monitor, case):
        self.__do_validate(monitor, case)

    def test_monitors_add_single(self):
        self.create_monitor('test')
        self.validate_all_monitors()

    def test_monitors_add_max(self):
        for i in range(10):
            self.create_monitor('test%d' % (i))
        with self.assertRaises(Exception):
            self.create_monitor('expected failure')
        self.validate_all_monitors()

    def test_monitors_add_enable_xmpp(self):
        case = self.create_monitor('test', enable_xmpp=True)
        new_case = case
        new_case[3] = False
        self.replace_case(case, new_case)
        self.validate_all_monitors()

    def test_monitors_add_enable_xmpp_as_admin(self):
        self.make_current_user_admin(True)
        self.create_monitor('test', enable_xmpp=True)
        self.validate_all_monitors()

    def test_monitors_add_enable_email(self):
        case = self.create_monitor('test', enable_email=True)
        new_case = case
        new_case[4] = False
        self.replace_case(case, new_case)
        self.validate_all_monitors()

    def test_monitors_add_enable_email_as_admin(self):
        self.make_current_user_admin(True)
        self.create_monitor('test', enable_email=True)
        self.validate_all_monitors()

    def test_monitors_get_single(self):
        self.create_monitor('extra1')
        case = self.create_monitor('test')
        self.create_monitor('extra2')
        monitor = models.Monitor.get(case[0])
        self.validate_monitor(monitor, case)
        self.validate_all_monitors()

    def test_monitors_get_all(self):
        for i in range(10):
            self.create_monitor('test%d' % (i))
        monitors = models.Monitor.getall()
        self.validate_all_monitors(monitors=monitors)
        self.validate_all_monitors()

    def test_monitors_get_nonexistent(self):
        case = self.create_monitor('test')
        self.delete_monitor_raw(case)
        with self.assertRaises(Exception):
            models.Monitor.get(case[0])
        self.validate_all_monitors()

    def test_monitors_get_nonpermitted(self):
        case = self.create_monitor('test')
        self.set_nonpermitted_user()
        with self.assertRaises(Exception):
            models.Monitor.get(case[0])
        self.validate_all_monitors()

    def test_monitors_get_badtype(self):
        self.create_monitor('test')
        class TestModel(ndb.Model):
            pass
        with self.assertRaises(Exception):
            models.Monitor.get(ndb.Key('TestModel', 'pretend').urlsafe())
        self.validate_all_monitors()

    def test_monitors_update_single(self):
        self.create_monitor('extra1')
        case = self.create_monitor('test')
        self.create_monitor('extra2')
        self.update_monitor(case, 'replacement')
        self.validate_all_monitors()

    def test_monitors_update_only_label(self):
        case = self.create_monitor('test')
        self.update_monitor(case, 'replacement',
            enable_xmpp=case[3], enable_email=case[4])
        self.validate_all_monitors()

    def test_monitors_update_only_xmpp(self):
        case = self.create_monitor('test')
        case = self.update_monitor(case, case[2],
            enable_xmpp=True, enable_email=case[4])
        expected = case
        expected[3] = False
        self.replace_case(case, expected)
        self.validate_all_monitors()

    def test_monitors_update_only_xmpp_as_admin(self):
        self.make_current_user_admin(True)
        case = self.create_monitor('test')
        self.update_monitor(case, case[2],
            enable_xmpp=True, enable_email=case[4])
        self.validate_all_monitors()

    def test_monitors_update_only_email(self):
        case = self.create_monitor('test')
        case = self.update_monitor(case, case[2],
            enable_xmpp=case[3], enable_email=True)
        expected = case
        expected[4] = False
        self.replace_case(case, expected)
        self.validate_all_monitors()

    def test_monitors_update_only_email_as_admin(self):
        self.make_current_user_admin(True)
        case = self.create_monitor('test')
        self.update_monitor(case, case[2],
            enable_xmpp=case[3], enable_email=True)
        self.validate_all_monitors()

    def test_monitors_update_nonexistent(self):
        case = self.create_monitor('test')
        self.delete_monitor_raw(case)
        with self.assertRaises(Exception):
            self.update_monitor(case, 'replacement')
        self.validate_all_monitors()

    def test_monitors_update_nonpermitted(self):
        case = self.create_monitor('test')
        self.set_nonpermitted_user()
        with self.assertRaises(Exception):
            self.update_monitor(case, 'replacement')
        self.validate_all_monitors()

    def test_monitors_update_badtype(self):
        case = self.create_monitor('test')
        class TestModel(ndb.Model):
            pass
        bad_case = [ndb.Key('TestModel', 'pretend').urlsafe()] + case[1:]
        with self.assertRaises(Exception):
            self.update_monitor(bad_case, 'replacement')
        self.validate_all_monitors()

    def test_monitors_locking(self):
        self.create_monitor('extra1')
        case = self.create_monitor('test')
        self.create_monitor('extra2')
        # false -> true
        case = self.lock_monitor(case, True)
        self.validate_all_monitors()
        # true -> true
        case = self.lock_monitor(case, True)
        self.validate_all_monitors()
        # true -> false
        case = self.lock_monitor(case, False)
        self.validate_all_monitors()
        # false -> false
        case = self.lock_monitor(case, False)
        self.validate_all_monitors()

    def test_monitors_locking_nonexistent(self):
        case = self.create_monitor('test')
        self.delete_monitor_raw(case)
        with self.assertRaises(Exception):
            self.lock_monitor(case, True)
        self.validate_all_monitors()

    def test_monitors_locking_nonpermitted(self):
        case = self.create_monitor('test')
        self.set_nonpermitted_user()
        with self.assertRaises(Exception):
            self.lock_monitor(case, True)
        self.validate_all_monitors()

    def test_monitors_locking_badtype(self):
        case = self.create_monitor('test')
        class TestModel(ndb.Model):
            pass
        bad_case = [ndb.Key('TestModel', 'pretend').urlsafe()] + case[1:]
        with self.assertRaises(Exception):
            self.lock_monitor(bad_case, True)
        self.validate_all_monitors()

    def test_monitors_delete_single(self):
        self.create_monitor('extra1')
        case = self.create_monitor('test')
        self.create_monitor('extra2')
        self.delete_monitor(case)
        self.validate_all_monitors()

    def test_monitors_delete_nonexistent(self):
        case = self.create_monitor('test')
        self.delete_monitor_raw(case)
        with self.assertRaises(Exception):
            self.delete_monitor(case)
        self.validate_all_monitors()

    def test_monitors_delete_nonpermitted(self):
        case = self.create_monitor('test')
        self.set_nonpermitted_user()
        with self.assertRaises(Exception):
            self.delete_monitor(case)
        self.validate_all_monitors()

    def test_monitors_delete_badtype(self):
        case = self.create_monitor('test')
        class TestModel(ndb.Model):
            pass
        bad_case = [ndb.Key('TestModel', 'pretend').urlsafe()] + case[1:]
        with self.assertRaises(Exception):
            self.delete_monitor(bad_case)
        self.validate_all_monitors()

