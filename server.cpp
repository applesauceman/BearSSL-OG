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
	//"Content-Length: 46\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html; charset=iso-8859-1\r\n"
	"\r\n"
	"<head><link rel=\"stylesheet\" href=\"https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css\"></head>"
	"<html>\r\n"
	"<body>\r\n"
	"<main class=\"container\"><h1>BearSSL Test by EqUiNoX</h1><a href=\"https://doomonline1.vercel.app/dos.html\" target=\"_blank\">Play Doom</a></main>\r\n"
	"</body>\r\n"
	"</html>\r\n";

static uint64_t WINAPI process(void* data) 
{
    uint16_t port = (uint16_t)data;

	int socket = socket_utility::host_bind(port);
	if (socket == INVALID_SOCKET) 
	{
		return EXIT_FAILURE;
	}

	unsigned char io_buffer[BR_SSL_BUFSIZE_BIDI];

	while (true)
	{
		int read_status = socket_utility::get_read_status(socket);
		if (read_status == SOCKET_ERROR)
		{
			return EXIT_FAILURE;
		}

		int client_socket = INVALID_SOCKET;
		if (read_status == 1)
		{
			client_socket = socket_utility::accept_client(socket);
		}
		else
		{
			Sleep(500);
			continue;
		}

		if (client_socket == INVALID_SOCKET) 
		{
			return EXIT_FAILURE;
		}

		br_ssl_server_context server_context;

#if SERVER_RSA /* RSA */
#if SERVER_PROFILE_MIN_FS
#if SERVER_CHACHA20
		br_ssl_server_init_mine2c(&server_context, CHAIN, CHAIN_LEN, &SKEY);
#else
		br_ssl_server_init_mine2g(&server_context, CHAIN, CHAIN_LEN, &SKEY);
#endif
#elif SERVER_PROFILE_MIN_NOFS
		br_ssl_server_init_minr2g(&server_context, CHAIN, CHAIN_LEN, &SKEY);
#else
		br_ssl_server_init_full_rsa(&server_context, CHAIN, CHAIN_LEN, &SKEY);
#endif
#elif SERVER_EC /* EC */
#if SERVER_PROFILE_MIN_FS
#if SERVER_CHACHA20
		br_ssl_server_init_minf2c(&server_context, CHAIN, CHAIN_LEN, &SKEY);
#else
		br_ssl_server_init_minf2g(&server_context, CHAIN, CHAIN_LEN, &SKEY);
#endif
#elif SERVER_PROFILE_MIN_NOFS
		br_ssl_server_init_minv2g(&server_context, CHAIN, CHAIN_LEN, &SKEY);
#else
		br_ssl_server_init_full_ec(&server_context, CHAIN, CHAIN_LEN, BR_KEYTYPE_EC, &SKEY);
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
		br_ssl_server_init_full_ec(&sc, CHAIN, CHAIN_LEN, BR_KEYTYPE_RSA, &SKEY);
#endif
#endif

		br_ssl_engine_set_buffer(&server_context.eng, io_buffer, BR_SSL_BUFSIZE_BIDI, 1);
		br_ssl_server_reset(&server_context);

		br_sslio_context io_context;
		br_sslio_init(&io_context, &server_context.eng, socket_utility::socket_read, &client_socket, socket_utility::socket_write, &client_socket);

		bool client_dropped = false;

		int feed_count = 0;
		while (true)
		{
			unsigned char current_char;
			if (br_sslio_read(&io_context, &current_char, 1) < 0) 
			{
				client_dropped = true;
				break;
			}
			if (current_char == 0x0D) 
			{
				continue;
			}
			if (current_char == 0x0A) 
			{
				if (feed_count == 1) 
				{
					break;
				}
				feed_count = 1;
			} 
			else 
			{
				feed_count = 0;
			}
		}

		if (client_dropped == false)
		{
			br_sslio_write_all(&io_context, HTTP_RES, strlen(HTTP_RES));
		}

		int error = br_ssl_engine_last_error(&server_context.eng);
		if (error == 0) 
		{
			debug_utility::debug_print("SSL closed (correctly).\n");
		} 
		else 
		{
			debug_utility::debug_print("SSL error: %d\n", error);
		}

		br_sslio_close(&io_context);
		closesocket(client_socket);
	}

	return 0;
}

void server::start(uint16_t port)
{
	thread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)process, (void*)port, 0, NULL);
}

void server::stop()
{
	//todo: wait stopped
	//CloseHandle(thread);
}




