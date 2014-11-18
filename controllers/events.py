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


class LoadRecent(base.RequestHandler):

    def post(self):
        events = models.Event.getrecent()
        events = [
            dict(
                monitor_key=e.monitor.urlsafe(),
                subject=e.subject,
                timestamp=str(e.timestamp))
            for e in events]
        response = dict(events=events)
        self.ajax(response)

class LoadPage(base.RequestHandler):

    def post(self):
        events, cursor, more = models.Event.getpage(
            models.Monitor.get(self.request.get('monitor-key')),
            cursor=self.request.get('cursor'))
        events = [
            dict(
                event_key=e.key.urlsafe(),
                subject=e.subject,
                message=e.message,
                timestamp=str(e.timestamp))
            for e in events]
        response = dict(events=events, cursor=cursor, more=more)
        self.ajax(response)

class Delete(base.RequestHandler):

    def post(self):
        models.Event.delete(self.request.get('event-key'))
        response = dict()
        self.ajax(response)
