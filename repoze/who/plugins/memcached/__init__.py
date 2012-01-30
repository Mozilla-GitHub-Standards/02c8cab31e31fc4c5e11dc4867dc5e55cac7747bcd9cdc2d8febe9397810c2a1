# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

repoze.who plugin to cache the results of other plugins.

"""

__ver_major__ = 0
__ver_minor__ = 1
__ver_patch__ = 1
__ver_sub__ = ""
__version__ = "%d.%d.%d%s" % (__ver_major__,__ver_minor__,__ver_patch__,__ver_sub__)


import os
import json
import hmac
import hashlib

import pylibmc

from zope.interface import implements
from repoze.who.api import get_api
from repoze.who.interfaces import IAuthenticator, IMetadataProvider


class MemcachedPlugin(object):
    """Cache IAuthenticator/IMetadataProvider plugin results using memcached.

    This is a repoze.who IAuthenticator/IMetadataProvider plugin that can
    cache the results of *other* plugins using memcached.  It's useful for
    reducing load on e.g. a backend LDAP auth system.

    To use it, give it the name of an authenticator and/or metadata provider
    whose results it should wrap::

        [plugin:ldap]
        use = my.ldap.authenticator

        [plugin:cached_ldap]
        use = repoze.who.plugins.memcached
        authenticator_name = ldap

        [authenticators]
        plugins = cached_ldap ldap;unused

    (The "ldap;unused" bit ensures that the wrapped ldap plugin still gets
    loaded, but is not used for matching any requests. Yeah, it's yuck.)

    To prevent a compromise of the cache from revealing auth credentials, this
    plugin calculates a HMAC hash of the items in the incoming identity and
    uses that as the cache key.  This makes it possible to check the cache for
    a match to an incoming identity, while preventing the cache keys from being 
    reversed back into a valid identity.

    Items added to the identity by the wrapped plugin will be stored in the
    cached value and will *not* be encryped or obfuscated in any way.

    The following configuration options are available:

        * memcached_urls:  A list of URLs for the underlying memcached store.

        * authenticator_name:  The name of an IAuthenticator plugin to wrap.

        * mdprovider_name:  The name of an IMetadataProvider plugin to wrap.
 
        * key_items:  A list of names from the identity dict that should be
                      hashed to produce the cache key.  These items should
                      uniquely and validly identity a user.  By default it
                      will use all keys in the identity in sorted order.

        * value_items:  A list of names from the identity dict that should be
                        stored in the cache.  These would typically be items
                        of metadata such as the user's email address.  By 
                        default this will include all items that the wrapped
                        plugin adds to the identity.

        * secret:  A string used when calculating the HMAC the cache keys.
                   All servers accessing a shared cache should use the same
                   secret so they produce the same set of cache keys.

        * ttl:  The time for which cache entries should persist, in seconds.

    """

    implements(IAuthenticator, IMetadataProvider)

    def __init__(self, memcached_urls, authenticator_name=None,
                 mdprovider_name=None, key_items=None, value_items=None,
                 secret=None, ttl=None):
        if authenticator_name is None and mdprovider_name is None:
            msg = "You must specify authenticator_name and/or "\
                  "mdprovider_name (otherwise this plugin won't "\
                  "actually do anything...)"
            raise ValueError(msg)
        if secret is None:
            secret = os.urandom(16)
        if ttl is None:
            ttl = 60
        self.memcached_urls = memcached_urls
        self.authenticator_name = authenticator_name
        self.mdprovider_name = mdprovider_name
        self.key_items = key_items
        self.value_items = value_items
        self.secret = secret
        self.ttl = ttl
        self._client = pylibmc.Client(memcached_urls)

    def authenticate(self, environ, identity):
        """Authenticate the identity from the given request environment.

        This method checks whether an entry matching the identity is currently
        stored in the cache.  If so, it loads data from the stored entry and
        return successfully.
        """
        # Only do anything if we're wrapping an authenticator.
        if self.authenticator_name is None:
            return None
        api = get_api(environ)
        if api is None:
            return None
        wrapped_authenticator = api.name_registry[self.authenticator_name]
        # Check if we've got cached data already.
        data = self._get_cached(environ, identity, "authenticate")
        if data is not None:
            identity.update(data)
            return identity.get("repoze.who.userid")
        # Not cached, check with the wrapped authenticator.
        value_items = self.value_items
        if value_items is None:
            old_keys = set(identity.iterkeys())
        userid = wrapped_authenticator.authenticate(environ, identity)
        if userid is None:
            return None
        # If that was successful, cache it along with any added data.
        # Make sure to always cache repoze.who.userid.
        if value_items is None:
            value_items = [k for k in identity.iterkeys() if k not in old_keys]
        identity.setdefault("repoze.who.userid", userid)
        value_items = ["repoze.who.userid"] + list(value_items)
        self._set_cached(environ, identity, value_items, "authenticate")
        return userid

    def add_metadata(self, environ, identity):
        """Add metadata to the given identity dict."""
        # Only do anything if we're wrapping an mdprovider.
        if self.mdprovider_name is None:
            return None
        api = get_api(environ)
        if api is None:
            return None
        wrapped_mdprovider = api.name_registry[self.mdprovider_name]
        # Check if we've got cached data already.
        data = self._get_cached(environ, identity, "add_metadata")
        if data is not None:
            identity.update(data)
            return None
        # Not cached, check with the wrapped mdprovider.
        value_items = self.value_items
        if value_items is None:
            old_keys = set(identity.iterkeys())
        wrapped_mdprovider.add_metadata(environ, identity)
        # Cache any data that was added.
        if value_items is None:
            value_items = [k for k in identity.iterkeys() if k not in old_keys]
        self._set_cached(environ, identity, value_items, "add_metadata")

    def _get_cached(self, environ, identity, method_name):
        """Get the cached data for the given identity, if any.

        If the given identity has previously been seen and stored in the
        cache, this method returns the dict of cached data.  If the identity
        is not cached then it returns None.
        """
        key = self._get_cache_key(environ, identity, method_name)
        # Grab it from the cache as a JSON string.
        try:
            value = self._client.get(key)
        except pylibmc.Error:
            return None
        # Parse it into a dict of data.
        try:
            value = json.loads(value)
        except ValueError:
            return None
        return value

    def _set_cached(self, environ, identity, value_items, method_name):
        """Set the cached data for the given identity.

        This method extracted the named value_items from the identity and
        stores them in the cache for future reference.  It ignores errors
        from writing to the cache.
        """
        key = self._get_cache_key(environ, identity, method_name)
        data = {}
        for name in value_items:
            try:
                data[name] = identity[name]
            except KeyError:
                pass
        try:
            self._client.set(key, json.dumps(data), time=self.ttl)
        except pylibmc.Error:
            pass
        
    def _get_cache_key(self, environ, identity, method_name):
        """Get the key under which to cache the given identity.

        The cache key is a hmac over all the items named in self.key_items
        if specified, or over all the values in sorted key order.  Using a
        hmac ensures that each identity has a unique key while not leaking
        credential information into memcached.

        A single instance of this plugin might cache results for both an
        authenticator and an mdprovider.  To prevent conflicts the name of
        the calling method is also included in the hash.
        """
        # We cache the key when first calculated, so that we always use the
        # value as it was first seen by the plugin.  This prevents cache
        # misses when some other plugin scribbles on the identity.
        envkey = "repoze.who.plugins.memcached.cache-key-" + method_name
        key = environ.get(envkey)
        if key is not None:
            return key
        # If no list of key items is specified, use all keys in sorted order.
        key_items = self.key_items
        if key_items is None:
            key_items = identity.keys()
            key_items.sort()
        # Hash in the method name and the value of all key items.
        hasher = hmac.new(self.secret, method_name, hashlib.sha1)
        hasher.update("\x00")
        for name in key_items:
            hasher.update(str(identity.get(name, "")))
            hasher.update("\x00")
        key = hasher.hexdigest()
        # Cache it for future reference.
        environ[envkey] = key
        return key


def make_plugin(memcached_urls, authenticator_name=None, mdprovider_name=None,
                key_items=None, value_items=None, secret=None, ttl=None):
    """CachedAuthPlugin helper for loading from ini files."""
    memcached_urls = memcached_urls.split()
    if not memcached_urls:
        raise ValueError("You must specify at least one memcached URL")
    if key_items is not None:
        key_items = key_items.split()
    if value_items is not None:
        value_items = value_items.split()
    if ttl is not None:
        ttl = int(ttl)
    plugin = MemcachedPlugin(memcached_urls, authenticator_name,
                             mdprovider_name,key_items, value_items,
                             secret, ttl)
    return plugin
