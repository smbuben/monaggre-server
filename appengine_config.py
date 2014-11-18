#
# This file is part of the Monaggrere project.
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

import os


def webapp_add_wsgi_middleware(app):
    # Enable appstats on the development server but not in production.
    if os.environ.get('SERVER_SOFTWARE', '').startswith('Dev'):
        from google.appengine.ext.appstats import recording
        app = recording.appstats_wsgi_middleware(app)
    return app

