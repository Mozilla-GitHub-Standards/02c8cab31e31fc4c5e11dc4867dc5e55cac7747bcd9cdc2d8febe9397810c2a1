============================
repoze.who.plugins.memcached
============================

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
