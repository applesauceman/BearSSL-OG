#include "server.h"
#include "debug_utility.h"
#include "socket_utility.h"

#include <xtl.h>
#include <winsockx.h>
#include <stdio.h>

#include <bearssl.h>


#if !(SERVER_RSA || SERVER_EC || SERVER_MIXED)
#define SERVER_RSA     1
#define SERVER_EC      0
#define SERVER_MIXED   0
#endif

#if SERVER_RSA
#include "chain-rsa.h"
#include "key-rsa.h"
#define SKEY   RSA
#elif SERVER_EC
#include "chain-ec.h"
#include "key-ec.h"
#define SKEY   EC
#elif SERVER_MIXED
#include "chain-ec+rsa.h"
#include "key-ec.h"
#define SKEY   EC
#else
#error Must use one of RSA, EC or MIXED chains.
#endif

static const char *HTTP_RES =
	"HTTP/1.0 200 OK\r\n"
	"Content-Length: 46\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html; charset=iso-8859-1\r\n"
	"\r\n"
	"<html>\r\n"
	"<body>\r\n"
	"<p>BearSSL Test!</p>\r\n"
	"</body>\r\n"
	"</html>\r\n";

int server::start()
{
	int fd;


	int port = 443;

	/*
	 * Ignore SIGPIPE to avoid crashing in case of abrupt socket close.
	 */
	//signal(SIGPIPE, SIG_IGN);

	/*
	 * Open the server socket.
	 */
	fd = socket_utility::host_bind(port);
	if (fd == INVALID_SOCKET) {
		return EXIT_FAILURE;
	}

	/*
	 * Process each client, one at a time.
	 */
	while (true)
	{
		int cfd;
		br_ssl_server_context sc;
		unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
		br_sslio_context ioc;
		int lcwn, err;

		cfd = socket_utility::accept_client(fd);
		if (cfd == INVALID_SOCKET) {
			return EXIT_FAILURE;
		}

#if SERVER_RSA
#if SERVER_PROFILE_MIN_FS
#if SERVER_CHACHA20
		br_ssl_server_init_mine2c(&sc, CHAIN, CHAIN_LEN, &SKEY);
#else
		br_ssl_server_init_mine2g(&sc, CHAIN, CHAIN_LEN, &SKEY);
#endif
#elif SERVER_PROFILE_MIN_NOFS
		br_ssl_server_init_minr2g(&sc, CHAIN, CHAIN_LEN, &SKEY);
#else
		br_ssl_server_init_full_rsa(&sc, CHAIN, CHAIN_LEN, &SKEY);
#endif
#elif SERVER_EC
#if SERVER_PROFILE_MIN_FS
#if SERVER_CHACHA20
		br_ssl_server_init_minf2c(&sc, CHAIN, CHAIN_LEN, &SKEY);
#else
		br_ssl_server_init_minf2g(&sc, CHAIN, CHAIN_LEN, &SKEY);
#endif
#elif SERVER_PROFILE_MIN_NOFS
		br_ssl_server_init_minv2g(&sc, CHAIN, CHAIN_LEN, &SKEY);
#else
		br_ssl_server_init_full_ec(&sc, CHAIN, CHAIN_LEN,
			BR_KEYTYPE_EC, &SKEY);
#endif
#else /* SERVER_MIXED */
#if SERVER_PROFILE_MIN_FS
#if SERVER_CHACHA20
		br_ssl_server_init_minf2c(&sc, CHAIN, CHAIN_LEN, &SKEY);
#else
		br_ssl_server_init_minf2g(&sc, CHAIN, CHAIN_LEN, &SKEY);
#endif
#elif SERVER_PROFILE_MIN_NOFS
		br_ssl_server_init_minu2g(&sc, CHAIN, CHAIN_LEN, &SKEY);
#else
		br_ssl_server_init_full_ec(&sc, CHAIN, CHAIN_LEN,
			BR_KEYTYPE_RSA, &SKEY);
#endif
#endif
		/*
		 * Set the I/O buffer to the provided array. We
		 * allocated a buffer large enough for full-duplex
		 * behaviour with all allowed sizes of SSL records,
		 * hence we set the last argument to 1 (which means
		 * "split the buffer into separate input and output
		 * areas").
		 */
		br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);

		/*
		 * Reset the server context, for a new handshake.
		 */
		br_ssl_server_reset(&sc);

		/*
		 * Initialise the simplified I/O wrapper context.
		 */
		br_sslio_init(&ioc, &sc.eng, socket_utility::socket_read, &cfd, socket_utility::socket_write, &cfd);

		/*
		 * Read bytes until two successive LF (or CR+LF) are received.
		 */
		lcwn = 0;
		while (true)
		{
			unsigned char x;

			if (br_sslio_read(&ioc, &x, 1) < 0) {
				goto client_drop;
			}
			if (x == 0x0D) {
				continue;
			}
			if (x == 0x0A) {
				if (lcwn) {
					break;
				}
				lcwn = 1;
			} else {
				lcwn = 0;
			}
		}

		/*
		 * Write a response and close the connection.
		 */
		br_sslio_write_all(&ioc, HTTP_RES, strlen(HTTP_RES));
		br_sslio_close(&ioc);

	client_drop:
		err = br_ssl_engine_last_error(&sc.eng);
		if (err == 0) {
			debug_utility::debug_print("SSL closed (correctly).\n");
		} else {
			debug_utility::debug_print("SSL error: %d\n", err);
		}
		closesocket(cfd);
	}
}




