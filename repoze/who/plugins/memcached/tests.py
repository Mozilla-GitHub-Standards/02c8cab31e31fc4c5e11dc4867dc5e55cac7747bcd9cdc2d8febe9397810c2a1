# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest

import os
import time
import wsgiref.util

from zope.interface import implements
from zope.interface.verify import verifyClass
from repoze.who.config import WhoConfig
from repoze.who.api import APIFactory
from repoze.who.interfaces import (IAuthenticator,
                                   IMetadataProvider,
                                   IIdentifier)

from repoze.who.plugins.memcached import MemcachedPlugin, make_plugin, pylibmc


WHO_CONFIG = """
[plugin:dummy_id]
use = repoze.who.plugins.memcached.tests:DummyIdentifier

[plugin:dummy_auth]
use = repoze.who.plugins.memcached.tests:DummyAuthenticator

[plugin:dummy_md]
use = repoze.who.plugins.memcached.tests:DummyMDProvider

[plugin:cached_auth]
use = repoze.who.plugins.memcached:make_plugin
memcached_urls = localhost:1234
authenticator_name = dummy_auth
mdprovider_name = dummy_md

[identifiers]
plugins = dummy_id

[authenticators]
plugins = cached_auth dummy_auth;unused

[mdproviders]
plugins = cached_auth dummy_md;unused

[general]
challenge_decider = repoze.who.classifiers:default_challenge_decider
request_classifier = repoze.who.classifiers:default_request_classifier
"""


class FakePyLibMCClient(object):
    """Fake pylibmc Client object, for testing purposes."""

    cache = {}

    def __init__(self, urls):
        pass

    def get(self, key):
        try:
            return self.cache[key]
        except KeyError:
            raise pylibmc.ReadError

    def set(self, key, value, time=None):
        self.cache[key] = value

    @classmethod
    def clear_cache(cls):
        cls.cache.clear()


def make_environ(extra=None, **kwds):
    """Construct a wsgi environ dict, with default values."""
    environ = {}
    if extra is not None:
        environ.update(extra)
    environ["wsgi.version"] = (1, 0)
    environ["wsgi.url_scheme"] = "http"
    environ["SERVER_NAME"] = "localhost"
    environ["SERVER_PORT"] = "80"
    environ["REQUEST_METHOD"] = "GET"
    environ["SCRIPT_NAME"] = ""
    environ["PATH_INFO"] = "/"
    environ.update(kwds)
    return environ


class DummyIdentifier(object):
    """IIdentifier that extracts all X-ID-* headers."""

    implements(IIdentifier)

    def identify(self, environ):
        identity = {}
        for header in environ:
            if header.startswith("HTTP_X_ID_"):
                key = header[10:].lower()
                identity[key] = environ[header]
        return identity

    def remember(self, environ, identity):
        raise RuntimeError("tests shouldn't call this")  # pragma: nocover

    def forget(self, environ, identity):
        raise RuntimeError("tests shouldn't call this")  # pragma: nocover


class DummyAuthenticator(object):
    """IAuthenticator with an on/off switch that can add arbitrary keys."""

    implements(IAuthenticator)

    def __init__(self):
        self.active = True
        self.extras = {}

    def authenticate(self, environ, identity):
        if not self.active:
            return None
        identity.update(self.extras)
        return identity.get("username")


class DummyMDProvider(object):
    """IMetadataprovider with an on/off switch that can add arbitrary keys."""

    implements(IMetadataProvider)

    def __init__(self):
        self.active = True
        self.extras = {}

    def add_metadata(self, environ, identity):
        if self.active:
            identity.update(self.extras)


class TestMemcachedPlugin(unittest.TestCase):

    def setUp(self):
        self._orig_Client = pylibmc.Client
        pylibmc.Client = FakePyLibMCClient
        pylibmc.Client.clear_cache()

    def tearDown(self):
        pylibmc.Client.clear_cache()
        pylibmc.Client = self._orig_Client
        del self._orig_Client

    def _make_api_factory(self):
        parser = WhoConfig("")
        parser.parse(WHO_CONFIG)
        return APIFactory(parser.identifiers,
                          parser.authenticators,
                          parser.challengers,
                          parser.mdproviders,
                          parser.request_classifier,
                          parser.challenge_decider)

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
        self.assertEquals(plugin.value_items, ["five"])
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

    def test_basic_caching_of_login(self):
        api_factory = self._make_api_factory()
        # If we disable the backing plugin then we can't authenticate.
        api_factory.authenticators[1][1].active = False
        environ = make_environ({"HTTP_X_ID_USERNAME": "test1"})
        api = api_factory(environ)
        self.assertEquals(api.authenticate(), None)
        # Re-enable it, we can login and have our credentials cached.
        api_factory.authenticators[1][1].active = True
        environ = make_environ({"HTTP_X_ID_USERNAME": "test1"})
        api = api_factory(environ)
        self.assertEquals(api.authenticate().get("username"), "test1")
        # Now if we disable it, we can still login using the cached values.
        api_factory.authenticators[1][1].active = False
        environ = make_environ({"HTTP_X_ID_USERNAME": "test1"})
        api = api_factory(environ)
        self.assertEquals(api.authenticate().get("username"), "test1")
        # But some other random user can't log in.
        environ = make_environ({"HTTP_X_ID_USERNAME": "test2"})
        api = api_factory(environ)
        self.assertEquals(api.authenticate(), None)

    def test_basic_caching_of_metadata(self):
        api_factory = self._make_api_factory()
        api_factory.mdproviders[1][1].extras = {"meta": "data"}
        # Prime the cache for the given user.
        environ = make_environ({"HTTP_X_ID_USERNAME": "test1"})
        api = api_factory(environ)
        self.assertEquals(api.authenticate().get("meta"), "data")
        # Now switch off the mdprovider, we can still use the cache.
        api_factory.mdproviders[1][1].active = False
        environ = make_environ({"HTTP_X_ID_USERNAME": "test1"})
        api = api_factory(environ)
        self.assertEquals(api.authenticate().get("username"), "test1")
        self.assertEquals(api.authenticate().get("meta"), "data")
        # Uncached users don't get the extra metadata.
        environ = make_environ({"HTTP_X_ID_USERNAME": "test2"})
        api = api_factory(environ)
        self.assertEquals(api.authenticate().get("username"), "test2")
        self.assertEquals(api.authenticate().get("meta"), None)

    def test_authenticator_can_be_disabled(self):
        api_factory = self._make_api_factory()
        api_factory.authenticators[0][1].authenticator_name = None
        # Log in will fail due to no wrapped authenticator.
        environ = make_environ({"HTTP_X_ID_USERNAME": "test1"})
        api = api_factory(environ)
        self.assertEquals(api.authenticate(), None)

    def test_mdprovider_can_be_disabled(self):
        api_factory = self._make_api_factory()
        api_factory.authenticators[0][1].mdprovider_name = None
        api_factory.authenticators[1][1].extras = {"auth": "enticator"}
        api_factory.mdproviders[1][1].extras = {"meta": "data"}
        # Logins will still work, but the mdprovider is not called.
        environ = make_environ({"HTTP_X_ID_USERNAME": "test1"})
        api = api_factory(environ)
        self.assertEquals(api.authenticate().get("username"), "test1")
        self.assertEquals(api.authenticate().get("auth"), "enticator")
        self.assertEquals(api.authenticate().get("meta"), None)

    def test_graceful_handling_of_non_repoze_environ(self):
        api_factory = self._make_api_factory()
        api_factory.mdproviders[1][1].extras = {"meta": "data"}
        # Log in will fail due to no repoze.who api in the environ.
        environ = make_environ({"HTTP_X_ID_USERNAME": "test1"})
        api = api_factory(environ)
        del environ["repoze.who.api"]
        self.assertEquals(api.authenticate(), None)
        # The same applies inside add_metadata.
        identity = {}
        api_factory.mdproviders[0][1].add_metadata(environ, identity)
        self.assertEquals(identity, {})

    def test_graceful_handling_of_cache_write_errors(self):
        api_factory = self._make_api_factory()
        def set_with_error(*args, **kwds):
            raise pylibmc.WriteError
        api_factory.authenticators[0][1]._client.set = set_with_error
        # Log in will succeed despite failed cache write.
        environ = make_environ({"HTTP_X_ID_USERNAME": "test1"})
        api = api_factory(environ)
        self.assertEquals(api.authenticate().get("username"), "test1")
        # But it won't be cached.
        api_factory.authenticators[1][1].active = False
        environ = make_environ({"HTTP_X_ID_USERNAME": "test1"})
        api = api_factory(environ)
        self.assertEquals(api.authenticate(), None)

    def test_graceful_handling_of_bad_cache_values(self):
        api_factory = self._make_api_factory()
        # Log in once to prime the cache.
        environ = make_environ({"HTTP_X_ID_USERNAME": "test1"})
        api = api_factory(environ)
        self.assertEquals(api.authenticate().get("username"), "test1")
        # Now corrupt the cached value.
        cache = api_factory.authenticators[0][1]._client.cache
        for key in cache:
            cache[key] = "I AM NOT VALID JSON"
        # Login attempts with backend disabled will gracefully fail.
        api_factory.authenticators[1][1].active = False
        environ = make_environ({"HTTP_X_ID_USERNAME": "test1"})
        api = api_factory(environ)
        self.assertEquals(api.authenticate(), None)
        # Login attempts with backend enabled will call through to it.
        api_factory.authenticators[1][1].active = True
        environ = make_environ({"HTTP_X_ID_USERNAME": "test1"})
        api = api_factory(environ)
        self.assertEquals(api.authenticate().get("username"), "test1")
        # That will have repaired to cache, so we can use it to login now.
        api_factory.authenticators[1][1].active = False
        environ = make_environ({"HTTP_X_ID_USERNAME": "test1"})
        api = api_factory(environ)
        self.assertEquals(api.authenticate().get("username"), "test1")

    def test_caching_of_extra_values_from_authenticator(self):
        api_factory = self._make_api_factory()
        api_factory.authenticators[1][1].extras = {"one": 1, "two": 2}
        # Log in to let the authenticator add its extra data.
        environ = make_environ({"HTTP_X_ID_USERNAME": "test1"})
        api = api_factory(environ)
        identity = api.authenticate()
        self.assertEquals(identity.get("one"), 1)
        self.assertEquals(identity.get("two"), 2)
        # Those new values should be restored from the cache.
        api_factory.authenticators[1][1].active = False
        environ = make_environ({"HTTP_X_ID_USERNAME": "test1"})
        api = api_factory(environ)
        identity = api.authenticate()
        self.assertEquals(identity.get("one"), 1)
        self.assertEquals(identity.get("two"), 2)

    def test_caching_of_specific_values_from_authenticator(self):
        api_factory = self._make_api_factory()
        api_factory.authenticators[0][1].value_items = ("one", "three")
        api_factory.authenticators[1][1].extras = {"one": 1, "two": 2}
        # Log in to let the authenticator add its extra data.
        environ = make_environ({"HTTP_X_ID_USERNAME": "test1"})
        api = api_factory(environ)
        identity = api.authenticate()
        self.assertEquals(identity.get("one"), 1)
        self.assertEquals(identity.get("two"), 2)
        # Only the specified value should be restored from the cache.
        api_factory.authenticators[1][1].active = False
        environ = make_environ({"HTTP_X_ID_USERNAME": "test1"})
        api = api_factory(environ)
        identity = api.authenticate()
        self.assertEquals(identity.get("one"), 1)
        self.assertEquals(identity.get("two"), None)

    def test_that_cache_key_includes_all_items(self):
        api_factory = self._make_api_factory()
        # Log in with a particular password.
        environ = make_environ(HTTP_X_ID_USERNAME="test1",
                               HTTP_X_ID_PASSWORD="password1")
        api = api_factory(environ)
        self.assertEquals(api.authenticate().get("username"), "test1")
        # That password will get cached
        api_factory.authenticators[1][1].active = False
        environ = make_environ(HTTP_X_ID_USERNAME="test1",
                               HTTP_X_ID_PASSWORD="password1")
        api = api_factory(environ)
        self.assertEquals(api.authenticate().get("username"), "test1")
        # But other passwords won't match it, so they fail.
        environ = make_environ(HTTP_X_ID_USERNAME="test1",
                               HTTP_X_ID_PASSWORD="password2")
        api = api_factory(environ)
        self.assertEquals(api.authenticate(), None)

    def test_that_cache_key_excludes_unspecified_items(self):
        api_factory = self._make_api_factory()
        api_factory.authenticators[0][1].key_items = ("username",)
        # Log in with a particular password.
        environ = make_environ(HTTP_X_ID_USERNAME="test1",
                               HTTP_X_ID_PASSWORD="password1")
        api = api_factory(environ)
        self.assertEquals(api.authenticate().get("username"), "test1")
        # That will get cached using just the username.
        api_factory.authenticators[1][1].active = False
        environ = make_environ(HTTP_X_ID_USERNAME="test1",
                               HTTP_X_ID_PASSWORD="password1")
        api = api_factory(environ)
        self.assertEquals(api.authenticate().get("username"), "test1")
        # So any old password will hit the same cache value.
        environ = make_environ(HTTP_X_ID_USERNAME="test1",
                               HTTP_X_ID_PASSWORD="password2")
        api = api_factory(environ)
        self.assertEquals(api.authenticate().get("username"), "test1")
