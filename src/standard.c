/*	Asterisk Manager Proxy
	Copyright (c) 2005-2008 David C. Troy <dave@popvox.com>

	This program is free software, distributed under the terms of
	the GNU General Public License.

	standard.c
	Standard I/O Handler
*/

#include "astmanproxy.h"

extern struct mansession *sessions;

/* Return a fully formed message block to session_do for processing */
int _read(struct mansession *s, struct message *m) {
	int res;

	for (;;) {
		res = get_input(s, m->headers[m->hdrcount]);
		if (debug>5) debugmsg("get_input returned line %d, res %d, %s", m->hdrcount + 1, res, m->headers[m->hdrcount]);

		if (strstr(m->headers[m->hdrcount], "--END COMMAND--")) {
				if (debug) debugmsg("Found END COMMAND");
				m->in_command = 0;
		}
		if (strstr(m->headers[m->hdrcount], "Response: Follows")) {
				if (debug) debugmsg("Found Response Follows");
				m->in_command = 1;
		}
		if (res > 0) {
			if (!m->in_command && *(m->headers[m->hdrcount]) == '\0' ) {
				break;
			} else if (m->hdrcount < MAX_HEADERS - 1) {
				m->hdrcount++;
			} else {
				m->in_command = 0; // reset when block full
			}
		} else if (res < 0) {
			if (debug) debugmsg("Read error %d getting line", res);
			break;
		}
	}
	if (debug>2) debugmsg("Returning standard block of %d lines, res %d", m->hdrcount, res);

	return res;
}

int _write(struct mansession *s, struct message *m) {
	int i, res;
	char w_buf[1500];	// Usual size of an ethernet frame
	int at;

	// Combine headers into a buffer for more effective network use.
	// This can have HUGE benefits under load.
	at = 0;
	if ( s->dead )
		return 0;
	pthread_mutex_lock(&s->lock);

	if (debug>2)
		debugmsg("Transmitting standard block of %d lines, fd %d", m->hdrcount, s->fd);

	for (i=0; !s->dead && i<m->hdrcount; i++) {
		if( ! strlen(m->headers[i]) )
			continue;
		res = 0;
		if( at > 0 && at + strlen(m->headers[i]) > 1480 ) {
			/* have existing buffer and we're about to blow that buffer, flush it */
			res = ast_carefulwrite(s, w_buf, at);
			at = 0;
			if ( res < 0 ) {
				s->dead = 1;
				break;
			}
		}
		if( strlen(m->headers[i]) > 1480 ) {
			/* too big, bypass buffer, above block ensures it has been flushed */
			res = ast_carefulwrite(s, m->headers[i], strlen(m->headers[i]));
			if ( res >= 0 )
				res = ast_carefulwrite(s, "\r\n", 2);
		} else {
			memcpy( &w_buf[at], m->headers[i], strlen(m->headers[i]) );
			memcpy( &w_buf[at+strlen(m->headers[i])], "\r\n", 2 );
			at += strlen(m->headers[i]) + 2;
		}
		if ( res < 0 )
			s->dead = 1;
	}
	if (!s->dead) {
		memcpy( &w_buf[at], "\r\n", 2 );
		at += 2;
		res = ast_carefulwrite(s, w_buf, at);
		if ( res < 0 )
			s->dead = 1;
	}
	pthread_mutex_unlock(&s->lock);

	return 0;
}

int _onconnect(struct mansession *s, struct message *m) {

	char banner[100];

	if( strlen( pc.forcebanner ) ) {
		sprintf(banner, "%s\r\n", pc.forcebanner);
	} else {
		sprintf(banner, "%s/%s\r\n", PROXY_BANNER, PROXY_VERSION);
	}
	pthread_mutex_lock(&s->lock);
	ast_carefulwrite(s, banner, strlen(banner));
	pthread_mutex_unlock(&s->lock);

	return 0;
}

