# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is repoze.who.plugins.memcached
#
# The Initial Developer of the Original Code is the Mozilla Foundation.
# Portions created by the Initial Developer are Copyright (C) 2011
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Ryan Kelly (rkelly@mozilla.com)
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
#
# ***** END LICENSE BLOCK *****

import unittest

import os
import time
import wsgiref.util

from zope.interface.verify import verifyClass
from repoze.who.interfaces import IAuthenticator, IMetadataProvider

from repoze.who.plugins.memcached import MemcachedPlugin, make_plugin


def make_environ(**kwds):
    environ = {}
    environ["wsgi.version"] = (1, 0)
    environ["wsgi.url_scheme"] = "http"
    environ["SERVER_NAME"] = "localhost"
    environ["SERVER_PORT"] = "80"
    environ["REQUEST_METHOD"] = "GET"
    environ["SCRIPT_NAME"] = ""
    environ["PATH_INFO"] = "/"
    environ.update(kwds)
    return environ


class TestMemcachedPlugin(unittest.TestCase):

    def test_implements(self):
        verifyClass(IAuthenticator, MemcachedPlugin)
        verifyClass(IMetadataProvider, MemcachedPlugin)

    def test_make_plugin(self):
        # Test that arguments get parsed and set appropriately.
        plugin = make_plugin(memcached_urls="127.0.0.2:3 127.0.0.1:4",
                             authenticator_name="myauth",
                             mdprovider_name="mymd",
                             key_items="one two three",
                             value_items="five",
                             secret="Ted Koppel is a robot",
                             ttl="42")
        self.assertEquals(plugin.memcached_urls,
                          ["127.0.0.2:3", "127.0.0.1:4"])
        self.assertEquals(plugin.authenticator_name, "myauth")
        self.assertEquals(plugin.mdprovider_name, "mymd")
        self.assertEquals(plugin.key_items, ["one", "two", "three"])
        self.assertEquals(plugin.value_items, ["five", "repoze.who.userid"])
        self.assertEquals(plugin.secret, "Ted Koppel is a robot")
        self.assertEquals(plugin.ttl, 42)
        # Test that you must specify memcached urls and a plugin.
        self.assertRaises(TypeError, make_plugin)
        self.assertRaises(ValueError, make_plugin, "")
        self.assertRaises(ValueError, make_plugin, "localhost", secret="HA")
        # Test that appropriate defaults get set.
        plugin = make_plugin("127.0.0.2:3", "auther")
        self.assertEquals(plugin.memcached_urls, ["127.0.0.2:3"])
        self.assertEquals(plugin.authenticator_name, "auther")
        self.assertEquals(plugin.mdprovider_name, None)
        self.assertEquals(plugin.key_items, None)
        self.assertEquals(plugin.value_items, None)
        self.failUnless(isinstance(plugin.secret, basestring))
        self.assertEquals(plugin.ttl, 60)
        # Test setting just the authenticator
        plugin = make_plugin(memcached_urls="127.0.0.2:3",
                             authenticator_name="auther")
        self.assertEquals(plugin.authenticator_name, "auther")
        self.assertEquals(plugin.mdprovider_name, None)
        # Test setting just the mdprovider
        plugin = make_plugin(memcached_urls="127.0.0.2:3",
                             mdprovider_name="mdprov")
        self.assertEquals(plugin.authenticator_name, None)
        self.assertEquals(plugin.mdprovider_name, "mdprov")
