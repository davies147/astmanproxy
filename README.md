### astmanproxy

Based on the original astmanproxy by David C. Troy - Original README below

### Docker

Thanks to Florian Taeger has generously made his Docker wrapper available here:
https://github.com/ftaeger/docker-astmanproxy

### Original README

```
astmanproxy README
(c) 2005-2008 David C. Troy, dave@popvox.com
------------------------------------------------------------------
FOREWORD & QUICK START

The need for a proxy to Asterisk's manager interface has been 
clear; almost all GUIs and other interfaces to asterisk implement a 
proxy of some kind.  Why?  A proxy offers:

 - A single persistent connection to asterisk
 - A more secure (non-root) TCP interface
 - Ability to offer filtered input/output
 - Less connections and networking load for asterisk

It can serve as the basis for an extensible application framework
for communication with multiple Asterisk servers.

Features include:

 - Multiple Input/Output formats: HTTP, XML, CSV, and Standard
 - SSL Support for clients & servers (including HTTPS clients)
 - API for addition of new, modular I/O formats
 - Ability to support communication with multiple Asterisk Servers
 - I/O Formats selectable on a per-client basis
 - Written in c/pthreads to be fast and robust

You can use Astmanproxy as the basis for a web-based application:
send it data using HTTP POST or HTTP GET, and receive XML output.
Or use HTTP POST and get Standard (text/plain) output back!
Astmanproxy speaks HTTP internally, so no web server is required!

You can use Astmanproxy as an XML feed for a .NET program that keeps 
track of Asterisk's state.  Or as an interface for injecting quick 
commands into multiple Asterisk boxes from your Python scripts.  The 
possibilities are limited only by your imagination.

To get started quickly, simply:
  make
  make install

Edit the configuration file:
  vi /etc/asterisk/astmanproxy.conf

Optionally edit the other config files:
  vi /etc/asterisk/astmanproxy.users
  vi /etc/asterisk/ssl.conf

Start the program:
  astmanproxy

To view debug output, start astmanproxy in debug mode:
  astmanproxy -d

For more debug output, add more -d's:
  astmanproxy -ddddddd

You may want to start astmanproxy at boot.  In that case, you might 
place it in /etc/rc.d/rc.local:
  /usr/local/sbin/astmanproxy

Please send your feedback!  We are looking for contributors to add 
support for new I/O formats and add new features!

Contributions:
  Paypal via dave@popvox.com; beer accepted at Astricon events

===================================================================
Additional Proxy Features

In addition to exposing the entire Asterisk Manager API as a 
pass-through, non-interpreting proxy, 'astmanproxy' can parse client
input where desired; this could be used in the future to add new
features that should exist in a proxy but that don't
necessarily need to be in Asterisk proper.

There are some proxy-specific headers that you can specify in your
applications now:

Server: (x.x.x.x|hostname)
   Specify a server to which to send your commands.  This should match
   the server name specified in your config file's "host" entry.
   If you do not specify a server, the proxy will pick the first one
   it finds -- fine in single-server configurations.

Some "ProxyActions" have been implemented which the Proxy responds to 
but does not pass on to Asterisk itself:

ProxyAction: ListSessions
   Outputs a list of all active client and server sessions

ProxyAction: SetOutputFormat
OutputFormat: (standard|xml)
   Sets the output format on a per-client basis

ProxyAction: SetAutoFilter
AutoFilter: (on|off|unique)
   Sets the AutoFilter property on a per-client basis
   (See autofiltering section below)

ProxyAction: Logoff
   Logs client out of Proxy and leaves Asterisk alone.

ProxyAction: ListIOHandlers
   Lists all available Input/Output Handlers
   Examples include Standard, XML, and CSV; more I/O
   formats may be added by creating new handler modules.

ProxyAction: AddServer
Server: (x.x.x.x|hostname)
Port: (5038|other)
Username: (username)
Secret: (secret)
Events: (on|off)
   Initiates a proxy connection to a new Asterisk Server; this
   has the same effect of including a host entry in your
   host= section of the configuration file.

ProxyAction: DropServer
Server: (x.x.x.x|hostname)
   Disconnects a proxy<->server session.  Hostname specified
   should exactly match the entry in your config host= section,
   or whatever name you used with ProxyAction: AddServer.

ProxyKey: secret
Action: Originate
...
ActionID: ...
   You can use this as a simple authentication mechanism.
   Rather than have to login with a username & password,
   you can specify a ProxyKey that must be passed from
   a client before requests are processed.  This is helpful
   in situations where you would like to authenticate and
   execute an action in a single step.  See the sample
   config file for more information.

The proxy also intercepts the following Actions:

Action: Login
   You can login to astmanproxy just as you would the Asterisk
   Manager Interface.  The user credentials are stored in
   astmanproxy.users.

Action: Challenge
   Astmanproxy now supports the MD5 challenge authentication
   mechanism.  See section below for more information on
   this authentication mechanism and how you can use it
   in your applications to avoid having to send a password
   over the internet, and instead use a MD5 challenge to
   hash your password before sending.  Note that this is
   somewhat less of an issue with SSL support now enabled,
   however, some apps require this mechanism, and we support it.

Action: Logoff
   You don't want your applications logging the proxy off of
   Asterisk. The proxy intercepts "Action: Logoff" and interprets
   it as "ProxyAction: Logoff".  This keeps the proxy from
   disconnecting from Asterisk.

Blank Commands
   The proxy does not send commands to Asterisk until you have
   a fully formed Action block.  This keeps unnecessary traffic
   and load off of Asterisk.  The proxy intercepts and ignores
   blank command blocks.

===================================================================
AstManProxy Autofiltering Functionality

One of the most powerful features of AstManProxy is its ability to
automatically filter output on a per-client basis.  It can do this
with its Autofilter capability, which can be set 'on'/'unique' in
the config file or enabled via the ProxyAction: SetAutoFilter function.

With autofiltering 'on', each client only receives output containing
the "ActionID" parameter it has set most recently.  This is useful
for single atomic requests into asterisk from a client, such as
when creating a simple UI to inject a command.

For example, if a client sends this packet while autofiltering is
enabled:

Action: Ping
ActionID: foo

Then the autofilter ActionID for that client is set to foo, and no
output besides for responses containing "foo" will be returned
to that client, such as:

Response: Pong
ActionID: foo

Replace Ping with Originate and Pong with Success and you can see
how this same mechanism can be used to quickly query asterisk
box(es), initiate calls, etc, without your client having to worry
with filtering a lot of unrelated output.

A more advanced verion of this facility is to set autofiltering to
'unique'. This causes astmanproxy to alter the ActionID on the way
to Asterisk, and undo that change on the way back.

For example the exchange:

> Action: Ping
> ActionID: foo
>

< Response: Pong
< ActionID: foo
<

Might be seen by Asterisk as:

> Action: Ping
> ActionID: amp7-foo
>

< Response: Pong
< ActionID: amp7-foo
<

and the "amp7-" prefix is created uniquely for each client connection.

===================================================================
On the astmanproxy.users output filtering functionality

Users may now be defined in your astmanproxy.users configuration file.
This enables a traditional user/password based login mechanism
for Astmanproxy similar to what is found in Asterisk.  Output may be
filtered on a per-user basis.

"user" is the username, secret is the password, and the (optional)
channel setting causes filtering of events only for the specified
channel to be sent to this user.

Following this, an outbound context and an inbound context may be
(optionally) specified. This will cause messages to and from
Asterisk respectively to be blocked if they contain a Context: header
which does not match the specified value. This might be used to
prevent a client making calls except in a predefined context.

An account code may be (optionally) specified. This will
force the Account: header to be overwritten for all commands to/from
this client. If the Action is "Originate", then a missing Account:
header will be added.

A "server" option will cause the proxy to behave as if the
client has included a "Server:" header in each request packet.

Any non-empty string provided in "more_events" will allow the passing
of non-filterable events to all clients. The default behaviour is to
block these packets if any form of filtering is requested.

Filters is a pipe-separated list of extra filter options. At present the following values have meaning:
	cdronly - Only pass Event: CDR records to this client. Other ???only filters are allowed.
	brionly - Only pass Event: Bridge events to this client. Other ???only filters are allowed.
	xfronly - Only pass Event: Transfer events to this client. Other ???only filters are allowed.
	novar - Pre-pass filter removes all SetVar/VarSet events

user=secret,channel,out_context (to Asterisk),in_context (From Asterisk),accountcode,server,more_events,filters

e.g.:
  steve=steve,SIP/snom190,local,
  dave=securepass,SIP/1002,,,davesaccount,daveserver,y,cdronly|novar
  bill=pass

NOTE: 'secret' can be a Blowfish salted/hashed password. This will be recognised by the fact it starts with a '$'

===================================================================
On the 'Action: Challenge' Authentication Mechanism

John Todd wrote this excellent summary of the Action: Challenge
Authentication Mechanism, and it accurately describes the
implementation included in astmanproxy:

While the SSL encryption of the AMI is great, it's always a good
policy to never send passwords at all if you have an alternative.

  After connecting to the AMI port, send this message:

   Action: Challenge
   AuthType: MD5

  You should receive a challenge string:
 
   Response: Success
   Challenge: 125065091

Then, assuming that the manager username is "joebob" and the
password is "yoyodyne11", perform this on a shell line of a handy
UNIX system (you programmers will figure out how to do this with a
library call, I'm sure):

   bash-3.00# md5 -s 125065091yoyodyne11
   MD5 ("125065091yoyodyne11") = e83a9e59e7c8d1bb6554982275d05016
   bash-3.00# 
 
  Now use this key to log in, so type this to the AMI:

    Action: Login
    AuthType: MD5
    Username: joebob
    Key: e83a9e59e7c8d1bb6554982275d05016

  ...and you'll get:

   Response: Success
   Message: Authentication accepted

===================================================================
On Astmanproxy's SSL Support

Support for SSL on the Asterisk Manager Interface has recently been
contributed to the Asterisk project (see Digium #6812).

This SSL implementation has been tested by several people and seems
to work fine.  While it is not in a mainline Asterisk distribution
yet (in SVN Trunk only right now), it is likely that AMI will soon
support SSL natively.

I felt that it was important that Astmanproxy support the same SSL
mechanism as Asterisk; we have been talking about adding SSL/TLS
for some time.  So, now it's been incorporated.

This means you can implement scenarios like:
      client <-> proxy <-> n*asterisk
with end-to-end SSL security.

To make Astmanproxy talk to asterisk, turn on the 'usessl' option
in the server host specification (see astmanproxy.conf).

To have Astmanproxy talk to clients via SSL, be sure to enable
'allowencryptedconnections' in the astmanproxy.conf file.

To have Astmanproxy accept ONLY SSL connections, you should
enable 'allowencryptedconnections' and disable
'allowunencryptedconnections'.  We've endeavored to use the same
configuration setting names as in manager.conf with the SSL
implementation in #6812.

===================================================================
Now Supports HTTPS Natively!

One really interesting side effect of having both SSL and HTTP support
natively is that we in fact now support HTTPS!

With the proxy configured on localhost:1234, you can do things
along these lines:

https://localhost:1234/?Action=ShowChannels&ActionID=Foo

This has been tested fairly extensively with good results.  The
HTTP handler supports both GET and POST and can properly deal
with XML or Standard output formats.  With Autofilter=on,
this paradigm is ideal for creating a simple REST-like interface
into Asterisk (even multiple boxes!) with no web servers needed.

===================================================================
Software Updates, Author Info, and How to Contribute

Current development on AstManProxy is happening here:
http://github.com/davetroy/astmanproxy/tree/master

Please feel free to fork and contribute!

Also, there is a new mailing list / group available here:
http://groups.google.com/group/astmanproxy?hl=en

===================================================================
AstManProxy Background Information
----------------------------------

Developing web-based realtime applications for the asterisk 
open-source PBX often requires interacting with asterisk's Manager 
interface.  The Asterisk Manager runs on port 5038 by default and 
provides a simple TCP interface into several common asterisk 
functions, including call origination, redirection, hangup, and many 
other functions.

Each interaction from a web-based application requires a separate 
connection to the manager interface.  Asterisk, being a real time 
application, shouldn't have to deal with the load of constant 
connections, disconnections, and authentications from a single 
trusted client, namely your web app.

In the same way that web developers have solved this problem for 
other similar services (imapproxy for IMAP web mail clients, 
database connection caches, etc), 'astmanproxy' sets out to solve 
this problem for asterisk.

This project started out as a simple proof-of-concept script called 
"simpleproxy.pl" which was made available in September 2004, 
following a discussion at the Astricon conference regarding the need 
for such a proxy.  That code was based on Nicolas Gudino's manager 
proxy for his excellent Flash Operator Panel.  Written in perl and 
as a single-threaded select-based "dumb" proxy, simpleproxy.pl has 
been widely used as a basis for experimentation, but I wanted 
something more robust and that could act as a basis for additional 
features.

Asterisk Manager Proxy is a multithreaded proxy server for Asterisk 
Manager written in c, and based on several of the same data 
structures and routines found in the asterisk manager itself.  This 
insures a very high degree of compatibility with Asterisk; it should 
also be very robust and scalable.

Asterisk Manager Proxy gives the ability to support multiple input
and output format -- implemented as abstracted I/O handlers -- and
these are configurable on a per-client basis. 

===================================================================
(C) 2005-2008 David C. Troy, dave@popvox.com
```
