/*	Asterisk Manager Proxy
	Copyright (c) 2005-2008 David C. Troy <dave@popvox.com>

	This program is free software, distributed under the terms of
	the GNU General Public License.

	proxyfunc.c
	Functions specific to the manager proxy, not found in standard Asterisk AMI
*/

#include "astmanproxy.h"
#include "md5.h"
#include <ow-crypt.h>

extern struct mansession *sessions;
extern struct iohandler *iohandlers;
extern pthread_mutex_t serverlock;
extern pthread_mutex_t userslock;
extern pthread_rwlock_t sessionlock;

void *ProxyListIOHandlers(struct mansession *s) {
	struct message m;
	struct iohandler *i;

	memset(&m, 0, sizeof(struct message));
	AddHeader(&m, "ProxyResponse: Success");

	i = iohandlers;
	while (i && (m.hdrcount < MAX_HEADERS - 1) ) {
		if (i->read)
			AddHeader(&m, "InputHandler: %s", i->formatname);
		if (i->write)
			AddHeader(&m, "OutputHandler: %s", i->formatname);
		i = i->next;
	}

	s->output->write(s, &m);
	return 0;
}

void *ProxyListSessions(struct mansession *s) {
	struct message m;
	struct mansession *c;
	char iabuf[INET_ADDRSTRLEN];

	memset(&m, 0, sizeof(struct message));
	AddHeader(&m, "ProxyResponse: Success");

	pthread_rwlock_rdlock(&sessionlock);
	c = sessions;
	while (c && (m.hdrcount < MAX_HEADERS - 4) ) {
		if (!c->server) {
			AddHeader(&m, "ProxyClientSession: %s", ast_inet_ntoa(iabuf, sizeof(iabuf), c->sin.sin_addr));
			AddHeader(&m, "ProxyClientActionID: %s", c->actionid);
			AddHeader(&m, "ProxyClientInputHandler: %s", c->input->formatname);
			AddHeader(&m, "ProxyClientOutputHandler: %s", c->output->formatname);
		} else 
			AddHeader(&m, "ProxyServerSession: %s", ast_inet_ntoa(iabuf, sizeof(iabuf), c->sin.sin_addr));
		c = c->next;
	}
	pthread_rwlock_unlock(&sessionlock);

	s->output->write(s, &m);
	return 0;
}

void *ProxySetOutputFormat(struct mansession *s, struct message *m) {
	struct message mo;
	char *value;

	value = astman_get_header(m, "OutputFormat");
	SetIOHandlers(s, s->input->formatname, value);

	memset(&mo, 0, sizeof(struct message));
	AddHeader(&mo, "ProxyResponse: Success");
	AddHeader(&mo, "OutputFormat: %s", s->output->formatname );

	s->output->write(s, &mo);

	return 0;
}

int ProxyChallenge(struct mansession *s, struct message *m) {
	struct message mo;
	char *actionid;

	actionid = astman_get_header(m, "ActionID");
	if ( strcasecmp("MD5", astman_get_header(m, "AuthType")) ) {
		SendError(s, "Must specify AuthType", actionid);
		return 1;
	}

	if (!*s->challenge)
		snprintf(s->challenge, sizeof(s->challenge), "%d", rand());

	memset(&mo, 0, sizeof(struct message));
	AddHeader(&mo, "Response: Success");
	AddHeader(&mo, "Challenge: %s", s->challenge);
	if( actionid && strlen(actionid) )
		AddHeader(&mo, "ActionID: %s", actionid);

	s->output->write(s, &mo);
	return 0;
}

void *ProxySetAutoFilter(struct mansession *s, struct message *m) {
	struct message mo;
	char *value;
	int i;

	value = astman_get_header(m, "AutoFilter");
	if ( !strcasecmp(value, "on") )
		i = 1;
	else if ( !strcasecmp(value, "unique") )
		i = 2;
	else
		i = 0;
	pthread_mutex_lock(&s->lock);
	s->autofilter = i;
	if( i == 2 )
	  snprintf(s->actionid, MAX_LEN - 20, "amp%d-", s->fd);
	else
	  s->actionid[0] = '\0';
	pthread_mutex_unlock(&s->lock);

	memset(&mo, 0, sizeof(struct message));
	AddHeader(&mo, "ProxyResponse: Success");
	AddHeader(&mo, "AutoFilter: %d", s->autofilter);

	s->output->write(s, &mo);

	return 0;
}

int AuthCrypt(char *pass, char *hash) {
	if (debug) {
		debugmsg("Crypt password=%s, hash=%s", pass, hash);
		debugmsg("I get hash=%s", crypt(pass, hash));
	}

	if (!strcmp(crypt(pass, hash), hash))
		return 0;
	else
		return 1;
}

int AuthMD5(char *key, char *challenge, char *password) {
	int x;
	int len=0;
	char md5key[256] = "";
	struct MD5Context md5;
	unsigned char digest[16];

	if (!*key || !*challenge || !*password )
	return 1;

	if (debug)
		debugmsg("MD5 password=%s, challenge=%s", password, challenge);

	MD5Init(&md5);
	MD5Update(&md5, (unsigned char *) challenge, strlen(challenge));
	MD5Update(&md5, (unsigned char *) password, strlen(password));
	MD5Final(digest, &md5);
	for (x=0;x<16;x++)
			len += sprintf(md5key + len, "%2.2x", digest[x]);
	if( debug ) {
		debugmsg("MD5 computed=%s, received=%s", md5key, key);
	}
	if (!strcmp(md5key, key))
		return 0;
	else
		return 1;
}

void *ProxyLogin(struct mansession *s, struct message *m) {
	struct message mo;
	struct proxy_user *pu;
	char *user, *secret, *key, *actionid;

	user = astman_get_header(m, "Username");
	secret = astman_get_header(m, "Secret");
	key = astman_get_header(m, "Key");
	actionid = astman_get_header(m, "ActionID");

	memset(&mo, 0, sizeof(struct message));
	if( actionid && strlen(actionid) > 0 )
		AddHeader(&mo, "ActionID: %s", actionid);
	if( debug )
		debugmsg("Login attempt as: %s/%s", user, secret);

	pthread_mutex_lock(&userslock);
	pu = pc.userlist;
	while( pu ) {
		if ( !strcmp(user, pu->username) ) {
			if (pu->secret[0] == '$') {
				if (AuthCrypt(secret, pu->secret)) {
					pu = pu->next;
					continue;
				}
			} else if (AuthMD5(key, s->challenge, pu->secret) && strcmp(secret, pu->secret) ) {
				pu = pu->next;
				continue;
			}

			AddHeader(&mo, "Response: Success");
			AddHeader(&mo, "Message: Authentication accepted");
			s->output->write(s, &mo);
			pthread_mutex_lock(&s->lock);
			s->authenticated = 1;
			strcpy(s->user.channel, pu->channel);
			strcpy(s->user.icontext, pu->icontext);
			strcpy(s->user.ocontext, pu->ocontext);
			strcpy(s->user.account, pu->account);
			strcpy(s->user.server, pu->server);
			strcpy(s->user.more_events, pu->more_events);
			s->user.filter_bits = pu->filter_bits;
			pthread_mutex_unlock(&s->lock);
			if( debug )
				debugmsg("Login as: %s", user);
			break;
		}
		pu = pu->next;
	}
	pthread_mutex_unlock(&userslock);

	if( !pu ) {
		SendError(s, "Authentication failed", actionid);
		pthread_mutex_lock(&s->lock);
		s->authenticated = 0;
		pthread_mutex_unlock(&s->lock);
		if( debug )
			debugmsg("Login failed as: %s/%s", user, secret);
	}

	return 0;
}

void *ProxyLogoff(struct mansession *s, struct message *m) {
	struct message mo;
	char *actionid = actionid = astman_get_header(m, "ActionID");
 
	memset(&mo, 0, sizeof(struct message));
	AddHeader(&mo, "Response: Goodbye");
	AddHeader(&mo, "Message: Thanks for all the fish.");
	if( actionid && strlen(actionid) > 0 )
		AddHeader(&mo, "ActionID: %s", actionid);
 
	s->output->write(s, &mo);
 
	destroy_session(s);
	if (debug)
		debugmsg("Client logged off - exiting thread");
	pthread_exit(NULL);
	return 0;
}

int ProxyAddServer(struct mansession *s, struct message *m) {
	struct message mo;
	struct ast_server *srv;
	int res = 0;

	/* malloc ourselves a server credentials structure */
	srv = malloc(sizeof(struct ast_server));
	if ( !srv ) {
		fprintf(stderr, "Failed to allocate server credentials: %s\n", strerror(errno));
		exit(1);
	}

	memset(srv, 0, sizeof(struct ast_server) );
	memset(&mo, 0, sizeof(struct message));
	strcpy(srv->ast_host, astman_get_header(m, "Server"));
	strcpy(srv->ast_user, astman_get_header(m, "Username"));
	strcpy(srv->ast_pass, astman_get_header(m, "Secret"));
	strcpy(srv->ast_port, astman_get_header(m, "Port"));
	strcpy(srv->ast_events, astman_get_header(m, "Events"));

	if (*srv->ast_host && *srv->ast_user && *srv->ast_pass && *srv->ast_port && *srv->ast_events) {
		pthread_mutex_lock(&serverlock);
		srv->next = pc.serverlist;
		pc.serverlist = srv;
		pthread_mutex_unlock(&serverlock);
		res = StartServer(srv);
	} else
		res = 1;

	if (res) {
		AddHeader(&mo, "ProxyResponse: Failure");
		AddHeader(&mo, "Message: Could not add %s", srv->ast_host);
	} else {
		AddHeader(&mo, "ProxyResponse: Success");
		AddHeader(&mo, "Message: Added %s", srv->ast_host);
	}

	s->output->write(s, &mo);
	return 0;
}

int ProxyDropServer(struct mansession *s, struct message *m) {
	struct message mo;
	struct mansession *srv;
	char *value;
	int res;

	memset(&mo, 0, sizeof(struct message));
	value = astman_get_header(m, "Server");

	pthread_rwlock_rdlock(&sessionlock);
	srv = sessions;
	while (*value && srv) {
		if (srv->server && !strcmp(srv->server->ast_host, value))
			break;
		srv = srv->next;
	}
	pthread_rwlock_unlock(&sessionlock);

	if (srv) {
		destroy_session(srv);
		debugmsg("Dropping Server %s", value);
		AddHeader(&mo, "ProxyResponse: Success");
		AddHeader(&mo, "Message: Dropped %s", value);
		res = 0;
	} else {
		debugmsg("Failed to Drop Server %s -- not found", value);
		AddHeader(&mo, "ProxyResponse: Failure");
		AddHeader(&mo, "Message: Cannot Drop Server %s, Does Not Exist", value);
		res = 1;
	}

	s->output->write(s, &mo);
	return res;
}

void *ProxyListServers(struct mansession *s) {
	struct message m;
	struct mansession *c;
	char iabuf[INET_ADDRSTRLEN];

	memset(&m, 0, sizeof(struct message));
	AddHeader(&m, "ProxyResponse: Success");

	pthread_rwlock_rdlock(&sessionlock);
	c = sessions;
	while (c) {
		if (c->server) {
			AddHeader(&m, "ProxyListServer I: %s H: %s U: %s P: %s E: %s ",
			ast_inet_ntoa(iabuf, sizeof(iabuf), c->sin.sin_addr),
			c->server->ast_host, c->server->ast_user,
			c->server->ast_port, c->server->ast_events);
		}

		c = c->next;
	}
	pthread_rwlock_unlock(&sessionlock);

	s->output->write(s, &m);
	return 0;
}


void *proxyaction_do(char *proxyaction, struct message *m, struct mansession *s)
{
	if (!strcasecmp(proxyaction,"SetOutputFormat"))
		ProxySetOutputFormat(s, m);
	else if (!strcasecmp(proxyaction,"SetAutoFilter"))
		ProxySetAutoFilter(s, m);
	else if (!strcasecmp(proxyaction,"ListSessions"))
		ProxyListSessions(s);
	else if (!strcasecmp(proxyaction,"AddServer"))
		ProxyAddServer(s, m);
	else if (!strcasecmp(proxyaction,"DropServer"))
		ProxyDropServer(s, m);
	else if (!strcasecmp(proxyaction,"ListServers"))
		ProxyListServers(s);
	else if (!strcasecmp(proxyaction,"ListIOHandlers"))
		ProxyListIOHandlers(s);
	else if (!strcasecmp(proxyaction,"Logoff"))
		ProxyLogoff(s, m);
	else
	proxyerror_do(s, "Invalid Proxy Action");

	return 0;
}

int proxyerror_do(struct mansession *s, char *err)
{
	struct message mo;

	memset(&mo, 0, sizeof(struct message));
	AddHeader(&mo, "ProxyResponse: Error");
	AddHeader(&mo, "Message: %s", err);

	s->output->write(s, &mo);

	return 0;
}

/* [do_]AddToStack - Stores an event in a stack for later repetition.
		indexed on UniqueID.
   If SrcUniqueID / DestUniqueID are present, store against both.
   If a record already exists, do nothing.
   withbody = 0, saves just the key (client).
   withbody = 1, saves a copy of whole message (server).
   withbody = 2, saves a copy of a newstate message (server).
*/
int do_AddToStack(char *uniqueid, struct message *m, struct mansession *s, int withbody)
{
	struct mstack *prev;
	struct mstack *t;

	pthread_mutex_lock(&s->lock);
	prev = NULL;
	t = s->stack;

	while( t ) {
		if( !strncmp( t->uniqueid, uniqueid, sizeof(t->uniqueid) ) )
		{
			if( withbody < 2 ) {
				// Already added
				pthread_mutex_unlock(&s->lock);
				return 0;
			} else
				// Found record to update
				break;
		}
		prev = t;
		t = t->next;
	}
	if( !t && withbody == 2 ) {
		// No record found to update.
		pthread_mutex_unlock(&s->lock);
		return 0;
	}
	if( s->depth >= MAX_STACK ) {
		struct mstack *newtop;

		newtop = s->stack->next;
		if( s->stack->message )
			free( s->stack->message );
		if( s->stack->state )
			free( s->stack->state );
		free( s->stack );
		s->stack = newtop;
		s->depth--;
	}
	if( !t && (t = malloc(sizeof(struct mstack))) ) {
		memset(t, 0, sizeof(struct mstack));
		strncpy( t->uniqueid, uniqueid, sizeof(t->uniqueid) );
		s->depth++;
		if( prev )
			prev->next = t;
		else
			s->stack = t;
	}
	if( t ) {
		char *msg = NULL;
		if( withbody ) {
			// Save the message, in a reduced form to save memory...
			int m_size;
			int i, j;

			m_size = 1;
			j = 0;
			for( i = 0; i < m->hdrcount; i++ ) {
				m_size += strlen(m->headers[i])+1;
			}
			if( m_size < MAX_STACKDATA && (msg = malloc(m_size)) ) {
				memset(msg, 0, m_size);
				if( withbody == 1 ) {
					if( t->message )
						free( t->message );
					t->message = msg;
				} else {
					if( t->state )
						free( t->state );
					t->state = msg;
				}
				for( i = 0; i < m->hdrcount; i++ ) {
					strncpy( msg + j, m->headers[i], m_size - j );
					*(msg + j + strlen(m->headers[i])) = '\n';
					j += strlen(m->headers[i]) + 1;
				}
			}
		}
		if( debug ) {
			if( withbody < 2 )
				debugmsg("Added uniqueid: %s to %s stack", uniqueid, withbody?"server":"client");
			else
				debugmsg("Newstate for uniqueid: %s to %s stack", uniqueid, withbody?"server":"client");
			if( withbody && msg )
				debugmsg("Cached message: %s", msg);
		}
	}
	pthread_mutex_unlock(&s->lock);
	return 1;
}
int AddToStack(struct message *m, struct mansession *s, int withbody)
{
	char *uniqueid;
	int ret, absent;

	ret=0;
	absent=0;

	uniqueid = astman_get_header(m, "Uniqueid");
	if( uniqueid[0] != '\0' ) {
		if( do_AddToStack(uniqueid, m, s, withbody) )
			ret |= ATS_UNIQUE;
	} else
		absent++;

	uniqueid = astman_get_header(m, "SrcUniqueID");
	if( uniqueid[0] != '\0' ) {
		if( do_AddToStack(uniqueid, m, s, withbody) )
			ret |= ATS_SRCUNIQUE;
	} else {
		uniqueid = astman_get_header(m, "Uniqueid1");
		if( uniqueid[0] != '\0' ) {
			if( do_AddToStack(uniqueid, m, s, withbody) )
				ret |= ATS_SRCUNIQUE;
		} else
			absent++;
	}

	uniqueid = astman_get_header(m, "DestUniqueID");
	if( uniqueid[0] != '\0' ) {
		if( do_AddToStack(uniqueid, m, s, withbody) )
			ret |= ATS_DSTUNIQUE;
	} else {
		uniqueid = astman_get_header(m, "Uniqueid2");
		if( uniqueid[0] != '\0' ) {
			if( do_AddToStack(uniqueid, m, s, withbody) )
				ret |= ATS_DSTUNIQUE;
		} else
			absent++;
	}

	if( s->user.more_events[0] != '\0' && absent == 3 )
		ret = 1;	// Want more/anonymous events
	if (debug > 4 )
		debugmsg("AddToStack for fd: %d returning: %d", s->fd, ret);
	return ret;
}


/* DelFromStack - Removes an item from the stack based on the UniqueID field.
*/
void DelFromStack(struct message *m, struct mansession *s)
{
	char *uniqueid;
	struct mstack *prev;
	struct mstack *t;

	uniqueid = astman_get_header(m, "Uniqueid");
	if( uniqueid[0] == '\0' )
		return;

	pthread_mutex_lock(&s->lock);
	prev = NULL;
	t = s->stack;

	while( t ) {
		if( !strncmp( t->uniqueid, uniqueid, sizeof(t->uniqueid) ) )
		{
			if( t->message )
				free( t->message );
			if( t->state )
				free( t->state );
			if( prev )
				prev->next = t->next;
			else
				s->stack = t->next;
			free( t );
			s->depth--;
			if( debug )
				debugmsg("Removed uniqueid: %s from stack", uniqueid);
			break;
		}
		prev = t;
		t = t->next;
	}
	pthread_mutex_unlock(&s->lock);
}

/* FreeStack - Removes all items from stack.
*/
void FreeStack(struct mansession *s)
{
	struct mstack *t, *n;

	pthread_mutex_lock(&s->lock);
	t = s->stack;

	while( t ) {
		n = t->next;		// Grab next entry BEFORE we free the slot
		if( t->message )
			free( t->message );
		if( t->state )
			free( t->state );
		free( t );
		t = n;
		s->depth--;
	}
	s->stack = NULL;
	if( debug && s->depth > 0 )
		debugmsg("ALERT! Stack may have leaked %d slots!!!", s->depth);
	if( debug )
		debugmsg("Freed entire stack.");
	pthread_mutex_unlock(&s->lock);
}

/* IsInStack - If the message has a UniqueID, and it is in the stack...
 */
int IsInStack(char* uniqueid, struct mansession *s)
{
	struct mstack *t;

	pthread_mutex_lock(&s->lock);
	t = s->stack;

	while( t ) {
		if( !strncmp( t->uniqueid, uniqueid, sizeof(t->uniqueid) ) )
		{
			pthread_mutex_unlock(&s->lock);
			return 1;
		}
		t = t->next;
	}
	pthread_mutex_unlock(&s->lock);
	return 0;
}

/* ResendFromStack - We want to resend a cached message from the stack please...
 * Look for "uniqueid" in cache of session "s", and reconstruct into message "m"
 * If a Newstate has been seen, it gets put into "m2"
 */
void ResendFromStack(char* uniqueid, struct mansession *s, struct message *m, struct message *m2)
{
	struct mstack *t;

	if( !m )
		return;

	if( debug )
		debugmsg("ResendFromStack: %s", uniqueid);

	pthread_mutex_lock(&s->lock);
	t = s->stack;

	while( t ) {
		if( !strncmp( t->uniqueid, uniqueid, sizeof(t->uniqueid) ) )
		{
			// Got message, pull from cache.
			int i, h, j;
			if( t->message ) {
				for( i=0,h=0,j=0; i < strlen(t->message) && i < MAX_STACKDATA - 1 && h < MAX_HEADERS - 1; i++ ) {
					if( t->message[i] == '\n' || i-j >= MAX_LEN ) {
						strncpy( m->headers[h], t->message + j, i-j );
						m->headers[h][MAX_LEN-1] = '\0';
						j = i + 1;
						if( debug )
							debugmsg("remade: %s", m->headers[h]);
						h++;
					}
				}
				m->hdrcount = h;
			} else
				m->hdrcount = 0;

			if( t->state ) {
				for( i=0,h=0,j=0; i < strlen(t->state) && i < MAX_STACKDATA - 1 && h < MAX_HEADERS - 1; i++ ) {
					if( t->state[i] == '\n' || i-j >= MAX_LEN ) {
						strncpy( m2->headers[h], t->state + j, i-j );
						m2->headers[h][MAX_LEN-1] = '\0';
						j = i + 1;
						if( debug )
							debugmsg("remade: %s", m2->headers[h]);
						h++;
					}
				}
				m2->hdrcount = h;
			} else
				m->hdrcount = 0;

			pthread_mutex_unlock(&s->lock);
			return;
		}
		t = t->next;
	}
	pthread_mutex_unlock(&s->lock);
	return;
}

int ValidateAction(struct message *m, struct mansession *s, int inbound) {
	char *channel;
	char *context;
	char *uchannel;
	char *ucontext;
	char *action;
	char *actionid;
	char *event;
	char *application;
	char *response;
	char *account;
	char *uniqueid;
	char *tmp;
	char *unmatched;
	char *cheaders[] = {"Channel","Channel1","Channel2","Source","Destination","DestinationChannel","ChannelCalling",NULL};
	char *uheaders[] = {"UniqueID","Uniqueid1","Uniqueid2","SrcUniqueId","DestUniqueID",NULL};
	char *appnames[] = {"Voicemail","VoicemailMain","Echo","Playback","Background","Agi","EAgi","DeadAgi","Read","Meetme","Chanspy",NULL};
	int i, j, cmatched, cfound, ufound;

	if( debug > 5 )
		debugmsg("ValidateAction called for fd: %d, %s", s->fd, inbound?"inbound":"outbound");
	if( pc.authrequired && !s->authenticated )
		return 0;

	if( inbound )	// Inbound from server to client
		ucontext = s->user.icontext;
	else		// Outbound from client to server
		ucontext = s->user.ocontext;
	uchannel = s->user.channel;

	// There is no other filering, so just return quickly.
	if( uchannel[0] == '\0' && ucontext[0] == '\0' && s->user.account[0] == '\0' && s->user.filter_bits == 0 ) {
		if( debug > 5 )
			debugmsg("Message validated - no filtering");
		return 1;
	}

	event = astman_get_header(m, "Event");

	// If any "FILT" rules fail, then stop processing afterwards.
	i = 1;
	// Handle special filter flags before IsInStack checks
	if( inbound ) {
		if( s->user.filter_bits & FILT_CDRONLY ) {
			if( !strcasecmp( event, "CDR" ) ) {
				if( debug )
					debugmsg("CDRONLY set. Is a CDR. Allowed");
				return 1;
			} else {
				i = 0;
			}
		}
		if( s->user.filter_bits & FILT_BRIONLY ) {
			if( !strcasecmp( event, "Bridge" ) ) {
				if( debug )
					debugmsg("BRIONLY set. Is a Bridge. Allowed");
				return 1;
			} else {
				i = 0;
			}
		}
		if( s->user.filter_bits & FILT_XFRONLY ) {
			if( !strcasecmp( event, "Transfer" ) ) {
				if( debug )
					debugmsg("XFRONLY set. Is a Transfer. Allowed");
				return 1;
			} else {
				i = 0;
			}
		}
		if( s->user.filter_bits & FILT_NOVAR ) {
			if( !strcasecmp( event, "Set" ) ) {
				if( debug )
					debugmsg("NOVAR set. Blocked Set");
				return 0;
			} else if( !strcasecmp( event, "SetVar" ) ) {
				if( debug )
					debugmsg("NOVAR set. Blocked SetVar");
				return 0;
			} else if( !strcasecmp( event, "VarSet" ) ) {
				if( debug )
					debugmsg("NOVAR set. Blocked VarSet");
				return 0;
			}
		}
		if( (s->user.filter_bits & FILT_ASTERIX) && !strcasecmp( event, "NewExten" )) {
			i = 0;
			application = astman_get_header(m, "Application");
			for( j=0; application != '\0' && appnames[j] != NULL; j++ ) {
				if( !strcasecmp( application, appnames[j] ) ) {
					i = 1;
					break;
				}
			}
			if( i == 0 && debug )
				debugmsg("FILT_ASTERIX set. Blocked Application: %s", application);
		}
	}
	if( i == 0 ) {
		if( debug )
			debugmsg("FILT_???ONLY rule blocked an event.");
		return 0;
	}

	unmatched = "";
	ufound = 0;
	for( i=0; uheaders[i] != NULL; i++ ) {
		uniqueid = astman_get_header(m, uheaders[i]);
		if( uniqueid[0] != '\0' && IsInStack(uniqueid, s) ) {
			if( debug )
				debugmsg("Message validated (%s): %s already allowed", uheaders[i], uniqueid);
			if( !strcasecmp( event, "Hangup" ) )
				DelFromStack(m, s);
			ufound = 1;
		} else if( *uniqueid ) {
			if( debug > 6 )
				debugmsg("UniqueID: %s not matched for this connection.", uniqueid);
			unmatched = uniqueid;
		}
	}
	if( ufound ) {
		if( *unmatched == '\0' ) {
			if( debug > 4 )
				debugmsg("-- No unmatched header found.");
			return 1;
		}
		if( *uchannel == '\0' ) {
			if( debug > 4 )
				debugmsg("-- chan filtering not enabled.");
			return 1;
		}

	// We are allowing based on UID, but also have an unmatched UID
	// If Channel matches, then also add that UID.
		for( i=0; cheaders[i] != NULL; i++ ) {
			channel = astman_get_header(m, cheaders[i]);
			if( channel[0] == '\0' )
				continue;	// No header by that name.
			if( !strncasecmp( channel, uchannel, strlen(uchannel) )) {	// We have a Channel: header, so save the UID
				if( debug > 4 )
					debugmsg("-- Chan match, adding secondary UniqueID: %s", unmatched);
				return AddToStack(m, s, 0) | 1;
			}
		}
		if( debug > 4 )
			debugmsg("-- No Chan match, NOT adding secondary UniqueID: %s", unmatched);
		return 1;
	}

	// Response packets rarely have any of the following fields included, so
	// we will return a response if the ActionID matches our last known ActionID
	response = astman_get_header(m, "Response");
	actionid = astman_get_header(m, ACTION_ID);
	if( response[0] != '\0' && actionid[0] != '\0' && !strcmp(actionid, s->actionid) ) {
		if (s->autofilter < 2 && !strcmp(actionid, s->actionid)) {
			if( debug > 5 )
				debugmsg("Message validated - actionID");
			return 1;
		} else if ( !strncmp(actionid, s->actionid, strlen(s->actionid)) ) {
			if( debug > 5 )
				debugmsg("Message validated - actionID");
			return 1;
		}
	}

	action = astman_get_header(m, "Action");
	if( uchannel[0] != '\0' ) {
		if( debug )
			debugmsg("Attempting filter using channel: %s", uchannel);
		cmatched = 0;
		cfound = 0;
		for( i=0; cheaders[i] != NULL && !cmatched; i++ ) {
			channel = astman_get_header(m, cheaders[i]);
			if( channel[0] == '\0' )
				continue;	// No header by that name.

			cfound++;
			if( !strncasecmp( channel, uchannel, strlen(uchannel) )) {	// We have a Channel: header, so filter on it.
				if( debug > 3 )
					debugmsg("Message not filtered (chan): %s due to match", channel);
				cmatched++;
			} else if( pc.filterlocal && !inbound && !strcasecmp( action, "Originate" ) && !strcasecmp( channel, "Local/" ) ) {
				// Exceptions even if we don't match
				if( pc.filterlocal == 1 ) {
					// Allow all Local/ channels
					if( debug > 3 )
						debugmsg("Message not filtered (chan): %s due to filterlocal", channel);
					cmatched++;
				} else if( pc.filterlocal == 2 ) {	// Allow with @ocontext
					if( !(tmp=strchr(channel, '@')) || strcmp( (tmp+1), ucontext ) ) {
						// if( debug ) {
						// 	debugmsg("Message filtered (chan): %s != %s", channel, uchannel);
						// 	debugmsg("filterlocal ->(context): %s != @%s", tmp?tmp:"", ucontext);
						// }
						// NOT MATCHED
					} else {
						if( debug > 3 )
							debugmsg("Message not filtered (chan): %s due to filterlocal", channel);
						cmatched++;
					}
				} else if( pc.filterlocal == 3 ) {	// Set @ocontext and allow
					if( (tmp=strchrnul(channel, '@')) ) {
						*tmp='@';
						strcpy( (tmp+1), ucontext );
						if( debug > 3 )
							debugmsg("Message not filtered (chan): %s due to filterlocal", channel);
						cmatched++;
					}
				}
			}
		}
		if( cfound && !cmatched ) {
			if( debug )
				debugmsg("Message filtered %d chan headers != %s", cfound, uchannel);
			return 0;
		}
	}

	context = astman_get_header(m, "Context");
	if( context[0] != '\0' && ucontext[0] != '\0' ) {
		if( strcmp( context, ucontext ) ) {
			if( debug )
				debugmsg("Message filtered (ctxt): %s != %s", context, ucontext);
			return 0;
		}
	}

	if( s->user.account[0] != '\0' ) {
		account = astman_get_header(m, "Account");
		if( !strcasecmp( action, "Originate" ) ) {
			if( debug )
				debugmsg("Got Originate. Account: %s, setting to: %s", account, s->user.account);
			if( account[0] == '\0' )
				AddHeader(m, "Account: %s", s->user.account);
			else
				strcpy(account, s->user.account);
		} else if( account[0] != '\0' ) {
			if( debug )
				debugmsg("Got Account: %s, setting to: %s", account, s->user.account);
			strcpy(account, s->user.account);
		}
	}

	// Outbound or unfiltered packets are validated.
	if( !inbound || (uchannel[0] == '\0' && ucontext[0] == '\0') ) {
		if( debug > 2 && !inbound )
			debugmsg("Validate Passing an outbound message.");
		if( debug > 2 && (uchannel[0] == '\0' && ucontext[0] == '\0') )
			debugmsg("Validate Passing msg with no context or channel filter.");
		return 1;
	}

	int res;
	res = AddToStack(m, s, 0);
	if( debug > 5 )
		debugmsg("AddToStack returned %d", res);
	return res;
}

void *SendError(struct mansession *s, char *errmsg, char *actionid) {
	struct message m;

	memset(&m, 0, sizeof(struct message));
	AddHeader(&m, "Response: Error");
	AddHeader(&m, "Message: %s", errmsg);
	if( actionid && strlen(actionid) )
		AddHeader(&m, "ActionID: %s", actionid);

	s->output->write(s, &m);

	return 0;
}

extern struct message *do_asterix_filt(struct message *m) {
	int i;
	char *tmp;
	struct message *res;
	char *headers[] = {
				"Response","Event","ActionID","Channeltype","ObjectName","ChanObjectType","IPaddress","IPport",
				"Dynamic","Status","RegExpire","Address-IP","Address-Port","SIP-Useragent","Reg-Contact","VoiceMailbox",
				NULL
			};

	tmp = astman_get_header(m, "ActionID");				/* Has no ActionID */
	if( tmp[0] == '\0' )
		return m;
	tmp = astman_get_header(m, "ChannelType");			/* Has no ChannelType, or not 'SIP' */
	if( tmp[0] == '\0' || strcasecmp( tmp, "SIP" ) )
		return m;
	tmp = astman_get_header(m, "ChanObjectType");			/* Has no ChanObjectType, or not 'peer' */
	if( tmp[0] == '\0' || strcasecmp( tmp, "peer" ) )
		return m;
	tmp = astman_get_header(m, "Response");
	if( tmp[0] == '\0' || strcasecmp( tmp, "Success" ) ) {		/* Not a Result: Success */
		tmp = astman_get_header(m, "Event");
		if( tmp[0] == '\0' || strcasecmp( tmp, "PeerEntry" ) )	/* And not an Event: PeerEntry */
			return m;
	}

	/* Duplicate and modify (reduce) the original frame to save bandwidth */

        if (! (res = malloc(sizeof(struct message))) )
                return m;
	res->hdrcount = 0;
	res->in_command = 0;
	res->session = m->session;
	for( i=0; headers[i] != NULL; i++ ) {
		tmp = astman_get_header(m, headers[i]);
		if( tmp[0] == '\0' )
			continue;	// No header by that name.
		AddHeader(res, "%s: %s", headers[i], tmp);
	}

	return res;
}
