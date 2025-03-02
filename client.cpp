#include "client.h"
#include "url_utility.h"
#include "debug_utility.h"
#include "network_utility.h"
#include "string_utility.h"
#include "socket_utility.h"
#include "certificates.h"

#include <xtl.h>
#include <stdio.h>
#include <bearssl.h>

int client::download_file(const char* url, const char* file_path)
{
	const int port = 443;

	char *host = NULL;
	char *path = NULL;
	if (url_utility::parse_url(url, &host, &path) == false)
	{
		return -1;
	}

	uint32_t host_ip = network_utility::resolve_host(host);

	int socket = socket_utility::connect_to_host(host_ip, port);

	certificates::initialize_trust_anchors();

	br_ssl_client_context client_context;
	br_x509_minimal_context cert_context;
	br_ssl_client_init_full(&client_context, &cert_context, certificates::get_trust_anchors(), certificates::get_num_trust_anchors());

	unsigned char io_buffer[BR_SSL_BUFSIZE_BIDI];
	br_ssl_engine_set_buffer(&client_context.eng, io_buffer, BR_SSL_BUFSIZE_BIDI, 1);
	br_ssl_client_reset(&client_context, host, 0);

	br_sslio_context ioc;
	br_sslio_init(&ioc, &client_context.eng, socket_utility::socket_read, &socket, socket_utility::socket_write, &socket);

	char* request = string_utility::format_string("GET %s HTTP/1.1\r\nHost: %s\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n", path, host);
	br_sslio_write_all(&ioc, request, strlen(request));
	br_sslio_flush(&ioc);

	FILE* file = fopen(file_path, "wb");
	if (file != NULL)
	{
		debug_utility::debug_print("File created\n");

		int bytes_written = 0;
		while (true)
		{
			unsigned char tmp[4096];
			memset(tmp, 0, sizeof(tmp));
			int rlen = br_sslio_read(&ioc, tmp, sizeof(tmp));
			bytes_written += rlen;
			if (rlen < 0) 
			{
				break;
			}
			fwrite(tmp, 1, rlen, file);
		}
		fclose(file);

		debug_utility::debug_print("File written\n");
	}
	else 
	{
		debug_utility::debug_print("failed to open file\n");
	}

	closesocket(socket);

	/*
	 * Check whether we closed properly or not. If the engine is
	 * closed, then its error status allows to distinguish between
	 * a normal closure and a SSL error.
	 *
	 * If the engine is NOT closed, then this means that the
	 * underlying network socket was closed or failed in some way.
	 * Note that many Web servers out there do not properly close
	 * their SSL connections (they don't send a close_notify alert),
	 * which will be reported here as "socket closed without proper
	 * SSL termination".
	 */
	if (br_ssl_engine_current_state(&client_context.eng) == BR_SSL_CLOSED) {
		int err;

		err = br_ssl_engine_last_error(&client_context.eng);
		if (err == 0) {
			debug_utility::debug_print("closed.\n");
			return EXIT_SUCCESS;
		} else {
			debug_utility::debug_print("SSL error %d\n", err);
			return EXIT_FAILURE;
		}
	} else {
		debug_utility::debug_print("socket closed without proper SSL termination\n");
		return EXIT_FAILURE;
	}
}
