Snap-auth provides authentication functionality for Snap.  Eventually this will
probably be moved into the snap package.  But we're starting it off in
a separate package until we get a better sense of how snap code will be
organized.

Notes
-----

The design philosophy is that we let the user choose a persistence/session
mechanism consistent with their application.  Other than that, we try provide
a turn-key solution, so as much as possible should be done here.  Random salt
generation, hashing, password verification, etc need special care to ensure the
cryptographic properties necessary for strong security.  The user should not
have to think about these concerns.

We provide some higher level functionality that can be used directly inside
your application's monad. This functionality helps you determine if there is an
authenticated user, require that one is present and get their credentials when
needed.

A Snap.Auth.Handlers module has also been included with default handlers to
address typical use cases, such as user signup, login and logout.

Currently this code requires the 0.3 branch of the Snap framework, which is due
to be released in the near future.

TODO List
---------

* Challenge/response authentication (http://pajhome.org.uk/crypt/md5/auth.html)
  This is needed to provide secure authentication without SSL.  The goal is to
  take as much of the burden as possible off the end user, which probably
  means including some Javascript code for use on the client side.  If the
  client is not javascript-enabled, then the user should have the option to
  failover seamlessly to less secure authentication (that transmits cleartext
  passwords across the network) or alert the user and disallow logins..  

* Support for "remember me" and "password reset" tokens.

