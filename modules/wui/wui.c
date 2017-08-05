/*
 * EVER/IP(R)
 * Copyright (c) 2017 kristopher tate & connectFree Corporation.
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * This project may be licensed under the terms of the GNU AFFERO General
 * Public License version 3. Corporate and Academic licensing terms are also
 * available. Contact <licensing@connectfree.co.jp> for details.
 *
 * connectFree, the connectFree logo, and EVER/IP are registered trademarks
 * of connectFree Corporation in Japan and other countries. connectFree
 * trademarks and branding may not be used without express writen permission
 * of connectFree. Please remove all trademarks and branding before use.
 *
 * See the LICENSE file at the root of this project for complete information.
 *
 */

#include <re.h>
#include <everip.h>

static struct http_sock *hsock;

static void http_req_handler( struct http_conn *conn
														, const struct http_msg *msg
														, void *arg)
{
	int err;
	/*char *buf = NULL;*/
	struct pl pl_peer, pl_dht, pl_atfield, pl_tol;
	(void)arg;

	pl_peer.p = "p";
	pl_peer.l = 1;

	pl_dht.p = "d";
	pl_dht.l = 1;

	pl_atfield.p = "a";
	pl_atfield.l = 1;

	pl_tol.p = "t";
	pl_tol.l = 1;

	/*err = re_sdprintf(&buf, "%H", uri_header_unescape, &msg->prm);
	if (err)
		goto error;*/

	/*pl_set_str(&nprm, buf);*/

	if (0 == pl_strcasecmp(&msg->path, "/")) {
		http_creply(conn, 200, "OK",
			    "text/html;charset=UTF-8",
			    "<h1>EVER/IP(R) Status Menu</h1>"
			    "<h2>Peer Information</h2>"
			    "<pre>%H</pre>"
			    "<h2>Database Information</h2>"
			    "<pre>%H</pre>"
			    "<h2>A.T. Field</h2>"
			    "<pre>%H</pre>"
			    "<h2>Tree of Life</h2>"
			    "<pre>%H</pre>"
			    "<footer>© connectFree Corporation. All rights reserved.<br />"
"connectFree, the connectFree logo, and EVER/IP are registered trademarks of connectFree.<br />"
"Other company and product names may be trademarks of their respective owners.</footer>"
				  ,ui_input_pl, &pl_peer
				  ,ui_input_pl, &pl_dht
				  ,ui_input_pl, &pl_atfield
				  ,ui_input_pl, &pl_tol
			    );
	} else {
		goto error;
	}
	/*mem_deref(buf);*/

	return;

error:
	/*mem_deref(buf);*/
	http_ereply(conn, 404, "Not Found");
}


static int module_init(void)
{
	int err;
	struct sa laddr;
	sa_set_str(&laddr, "::1", 1988);

	err = http_listen( &hsock
									 , &laddr
									 , http_req_handler
									 , NULL);
	if (err)
		return err;

	info("webui: listening on %J\n", &laddr);

	return 0;
}


static int module_close(void)
{
	hsock = mem_deref(hsock);
	return 0;
}


const struct mod_export DECL_EXPORTS(wui) = {
	"wui",
	"app",
	module_init,
	module_close
};
