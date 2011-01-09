Snap-auth provides authentication and session management functionality for
Snap.  Eventually this will probably be moved into the snap package.  But we're
starting it off in a separate package until we get a better sense of how snap
code will be organized.


## The Concept

User/session management has two basic levels (potentially more if you add
permissions/roles/etc.):

  - Making sure an established session between any user - authenticated or
  	otherwise - and the server stays secure.
  - Authenticating users, which means having proof that a user is who she says
  	she is before we grant her some important priveleges in our application.

This package both of these challenges. It will likely be integrated into Snap
as the stock solution, possibly in the 0.5 release.  


## Session Management

First, let's demonstrate the session management piece.

### Introduction

For those familiar with Rails, the functionality is similar to 
    
    session[:user_id] = 1234
    session[:last_query] = "johnpollak"

The difference, however, is that we can't just store arbitrary data -types and
instead use only ByteStrings.


We define a type Session as

    type Session = Map ByteString ByteString

which gives us all the convenience and power of Haskell's standard Map library.

It is yet to be seen if this is effective and/or efficient in the long run but
has worked well so far.


### Setting Up Your Application With Sessions

Let's setup the session functionality using the CookieSession backend.
    
    -- Define a field to hold the session state in your application state
    data ApplicationState = ApplicationState
      { appSessionSt :: CookieSessionState }

    -- Instantiate your app as a MonadSession
    instance HasCookieSessionState ApplicationState where
      getCookieSessionState = appSessionSt

    -- Add some simple initializer code
    appInit :: Initializer ApplicationState
    appInit = do
      cs <- cookieSessionStateInitializer $ defCookieSessionState
              { csKeyPath = "config/site-key.txt" 
              , csCookieName = "myapp-session" }
      return $ ApplicationState cs


And you are done. While you have to do this manually for now, we will in the
future have the snap executable auto-generate some of this boiler plate
for you.


### Usage Example

Let's assume we have an odd desire to persist our user's age in our session
store: 

    import qualified Data.Map as M
    import           Snap.Extension.CookieSession
    
    ...

    myHandler = do
      setInSession "user_age" "32" -- that's all we have to do!
      render "pages/myPage"

The "user_age" field will now be available in this user's session until we
delete it or expire the session.

We can now retrieve it at any point with:
    
    myHandler2 = do
      uage <- getFromSession "user_age"
      doSomethingWithUid uage
      render "pages/myPage2"



### Backends


#### CookieSession

There is currently a single back-end: Snap.Extension.Session.CookieSession. It
uses Data.Serialize to serialize the Session data type and Michael Snoyman's
Web.ClientSession to encrypt the cookie. The cookie is encrypted, which means
it is fully secure and can't be read by the client/end-user.

Since this method has no need for a DB back-end, it works out of the box and is
pretty much the simplest session persistence back-end to use. For those
familiar, this method is the default behavior in Ruby on Rails as well.

Please see the Haddock documentation for more information.


### Other Backends

The idea would be to add various other back-ends as desired. Redis, MongoDB,
SQL-based databases, etc. should all be straightforward enough to implement. We
would just need a scheme to presist the session type in the respective
database.



## Authentication

The second layer of thic package provides for user athentication. It defines an
AuthUser datatype that holds all of the core authentication fields for
a "user". Let's look at it so we can get a sense for what is possible:


    data AuthUser = AuthUser 
      { userId :: Maybe UserId
      , userEmail :: Maybe ByteString
      , userPassword :: Maybe Password
      , userSalt :: Maybe ByteString
      , userActivatedAt :: Maybe UTCTime
      , userSuspendedAt :: Maybe UTCTime
      , userLoginCount :: Int
      , userFailedLoginCount :: Int
      , userCurrentLoginAt :: Maybe UTCTime
      , userLastLoginAt :: Maybe UTCTime
      , userCurrentLoginIp :: Maybe ByteString
      , userLastLoginIp :: Maybe ByteString
      , userCreatedAt :: Maybe UTCTime
      , userUpdatedAt :: Maybe UTCTime
      } deriving (Read,Show,Ord,Eq)


The authentication piece has two key typeclasses that we need to be aware of.

### MonadAuth Typeclass

To enable authentication, we need to make our application monad an instance of
MonadAuth. While doing so, we get to choose/customize various authentication
parameters. The simplest way to instantiate our application is simply:

    instance MonadAuth Application

and done. That's right, we have all the sensible defaults set up so you could
potentially just do that. More typically, here is what you would
specify:

    instance MonadAuth Application where
      authAuthenticationKeys = return ["login", "domain"]
      authUserTable = return "myusers"

and so on. Take a look at haddocks to see what can be specified.

NOTE: We are still working on implementing some of these options, but it should
be complete soon enough.

### MonadAuthUser Typeclass

Now onto the database integration. This typeclass is all about persisting users
in some form of storage. Whatever snap database extension is being used would
be expected to instantiate this typeclass and have nice integration with
MonadAuth. 

As an example, Snap.Extension.DB.MongoDB has ongoing support for MonadAuth and
instantiates MonadAuthUser for free. See the repo at:

    https://github.com/ozataman/snap-extension-mongodb

A couple of key ideas to understand this typeclass are as follows:
  
  1. User can be looked up in 2 ways: 
      - With an internal/db-provided unique bytestring identifier. This is the
      	"id" field in most db systems.
      - A Map of key, value pairs that can be used to look up a user in the db.
      	This is the external interface and is typically submitted through a web
      	form. This is how the user of you application will identify herself
      	during login.
  1. The user table in the DB can contain more fields than necessary for
     authentication. This is both natural and typical. So the saveAuthUser
     function takes a (AuthUser, t) input. AuthUser contains the core
     authentication fields and t is passed directly to the DB back-end to be
     included in the save. As an example, in MongoDB implementation t is the
     Document datatype and is merged with the AuthUser fields prior to database
     save.

Again, this typeclass is instantiated by the DB extension you are using, so
normally you should not need to implement it.

### Usage Example

Here is a simple example. We'll provide more thorough documentation as things
crystallize.


    data User = User
      { authUser :: AuthUser
      , myField1 :: ByteStrings
      , myField2 :: ByteStrings
      }

    -- Construct your 'User' from the given parameters
    -- Make sure you do validation as well - at least for now.
    makeUser ps = return $ User { .... }

    additionalUserFields :: User -> Document
    additionalUserFields u = [ "myField1" =: myField1 u
                             , "myField2" =: myField2 u ]
    
    site = routes $
      [ ("/signup", method GET $ newSignupH)
      , ("/signup", method POST $ signupH)

      , ("/login", method GET $ newSessionH)
      , ("/login", method POST $ loginHandler "password" newSessionH redirHome)
      ]

    redirHome = redirect "/"

    -- Make sure you have a 'password' field in there
    newSessionH = render "login"

    -- Assuming you have a signup.tpl template
    newSignupH = render "signup"

    -- Save user and redirect as appropriate
    signupH :: Application ()
    signupH = do
      ps <- getParams
      let u = makeUser ps
      au <- saveAuthUser (u, additionalUserFields u)
      case au of
        Nothing -> newSignupH
        Just au' -> do setSessionUserId $ userId au'
                       redirect "/"



## TODO/ROADMAP

### Session-related

#### General

- Splices/handlers for easy CSRF protection token integration:
  - csrf_meta_tag for unobtrusive JS based binding to forms (like in Rails 3)
  - csrf_token_tag for a hidden field inside forms (in progress)
  - verify_authenticity handler to be chained before your destructive handlers

#### Planned Back-ends
- MongoDB backend
- HDBC-based SQL back-ends once extension-hdbc is in place

#### Open Questions/Considerations
- Possibility of using JSON-like datatype for session store.

### Auth-related

- Challenge/response authentication (http://pajhome.org.uk/crypt/md5/auth.html)
  This is needed to provide secure authentication without SSL.  The goal is to
  take as much of the burden as possible off the end user, which probably
  means including some Javascript code for use on the client side.  If the
  client is not javascript-enabled, then the user should have the option to
  failover seamlessly to less secure authentication (that transmits cleartext
  passwords across the network) or alert the user and disallow logins..  

- Support for "remember me" and "password reset" tokens.

