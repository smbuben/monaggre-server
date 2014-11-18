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

import base
import models


class Display(base.RequestHandler):

    def get(self, monitor_key):
        monitor = models.Monitor.get(monitor_key)
        template_vals = {
            'monitor' : monitor,
        }
        self.render('monitor.html', **template_vals)

class Create(base.RequestHandler):

    def post(self):
        monitor_key = models.Monitor.create(
            self.request.get('monitor-label'),
            self.request.get('monitor-xmpp-notification') == 'on',
            self.request.get('monitor-email-notification') == 'on')
        self.go('/monitor/' + monitor_key)

class Update(base.RequestHandler):

    def post(self):
        monitor_key = self.request.get('monitor-key')
        models.Monitor.update(
            monitor_key,
            self.request.get('monitor-label'),
            self.request.get('monitor-xmpp-notification') == 'on',
            self.request.get('monitor-email-notification') == 'on')
        self.ajax(dict())

class Lock(base.RequestHandler):

    def post(self):
        monitor_key = self.request.get('monitor-key')
        models.Monitor.lock(monitor_key, True)
        self.ajax(dict())

class Unlock(base.RequestHandler):

    def post(self):
        monitor_key = self.request.get('monitor-key')
        models.Monitor.lock(monitor_key, False)
        self.ajax(dict())

class Delete(base.RequestHandler):

    def post(self):
        monitor_key = self.request.get('monitor-key')
        models.Monitor.delete(monitor_key)
        models.Event.deleteall(monitor_key)
        self.home()

