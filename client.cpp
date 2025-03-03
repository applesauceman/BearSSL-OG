#include "client.h"
#include "url_utility.h"
#include "debug_utility.h"
#include "network_utility.h"
#include "string_utility.h"
#include "socket_utility.h"
#include "certificates.h"
#include "data_store.h"

#include <xtl.h>
#include <stdio.h>
#include <stdint.h>
#include <bearssl.h>

#define READ_BUFFER_SIZE 65536

int client::download_file(const char* url, uint16_t port, const char* file_path)
{
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

	br_sslio_context io_context;
	br_sslio_init(&io_context, &client_context.eng, socket_utility::socket_read, &socket, socket_utility::socket_write, &socket);

	char* request = string_utility::format_string("GET %s HTTP/1.1\r\nHost: %s\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n", path, host);
	br_sslio_write_all(&io_context, request, strlen(request));
	br_sslio_flush(&io_context);

	data_store* data = new data_store();
	pointer_vector<char*>* headers = new pointer_vector<char*>(false);
	populate_headers(io_context, data, headers);

	int64_t content_length = -1;
	char* redirect_url = NULL;
	
	bool has_redirect = false;
	for (uint32_t i = 0; i < headers->count(); i++)
	{
		pointer_vector<char*>* parts = string_utility::split_first(headers->get(i), ":", true);
		if (parts->count() != 2)
		{
			continue;
		}
		if (strcmp(parts->get(0), "Content-Length") == 0)
		{
			content_length = string_utility::string_to_int64(parts->get(1));
		}
		if (strcmp(parts->get(0), "Location") == 0)
		{
			has_redirect = true;
			redirect_url = strdup(parts->get(1));
		}
		delete parts;
	}

	delete headers;

	if (has_redirect == true)
	{
		closesocket(socket);
		certificates::close_trust_anchors();
		delete data;

		int result;
		result = download_file(redirect_url, port, file_path);
		if (redirect_url != NULL)
		{
			free(redirect_url);
		}
		return result;;
	}

	if (redirect_url != NULL)
	{
		free(redirect_url);
	}

	if (content_length < 0)
	{
		chunk_download(io_context, data, file_path);
	}
	else
	{
		download(io_context, data, file_path, content_length);
	}

	closesocket(socket);
	certificates::close_trust_anchors();
	delete data;

	if (br_ssl_engine_current_state(&client_context.eng) == BR_SSL_CLOSED) 
	{
		int error = br_ssl_engine_last_error(&client_context.eng);
		if (error == 0) 
		{
			debug_utility::debug_print("Closed.\n");
			return EXIT_SUCCESS;
		} 
		else 
		{
			debug_utility::debug_print("SSL error %d\n", error);
			return EXIT_FAILURE;
		}
	} 

	debug_utility::debug_print("Socket closed without proper SSL termination\n");
	return EXIT_FAILURE;
}

// Private

void client::populate_headers(br_sslio_context io_context, data_store* data, pointer_vector<char*>* headers)
{
	unsigned char* read_buffer = (unsigned char*)malloc(READ_BUFFER_SIZE);

    while (true)
    {
		int bytes_read = br_sslio_read(&io_context, read_buffer,READ_BUFFER_SIZE);
		if (bytes_read < 0) 
		{
			break;
		}

		data->add_range(read_buffer, 0, bytes_read);

		bool eof_headers = false;
		while (true)
		{
			unsigned char* data_buffer = data->get_all();
			int offset = string_utility::find_crlf(data_buffer, data->count());
			if (offset < 0)
			{
				break;
			}
			char* hearder_line = (char*)malloc(offset + 1);
			memcpy(hearder_line, data_buffer, offset);
			hearder_line[offset] = 0;
			if (hearder_line[0] == 0)
			{
				free(hearder_line);
				data->remove_range(0, offset + 2);
				eof_headers = true;
				break;
			}

			debug_utility::debug_print("Header Line: %s\n", hearder_line);
			headers->add(hearder_line);
			data->remove_range(0, offset + 2);
		}

		if (eof_headers == true)
		{
			break;
		}
    }

	free(read_buffer);
}

void client::chunk_download(br_sslio_context io_context, data_store* data, const char* file_path)
{
	unsigned char* read_buffer = (unsigned char*)malloc(READ_BUFFER_SIZE);

	FILE* file = fopen(file_path, "wb");

	int chunk_size = 0;
	bool looking_for_chunk_header = true;

	int64_t bytes_written = 0;
    while (true)
    {
        int bytes_read = br_sslio_read(&io_context, read_buffer,READ_BUFFER_SIZE);
		if (bytes_read < 0) 
		{
			break;
		}

		data->add_range(read_buffer, 0, bytes_read);

		if (looking_for_chunk_header == true)
		{
			unsigned char* data_buffer = data->get_all();
			int offset = string_utility::find_crlf(data_buffer, data->count());
			if (offset < 0)
			{
				continue;
			}
			
			char* chunk_hex = (char*)malloc(offset + 1);
			memcpy(chunk_hex, data_buffer, offset);
			chunk_hex[offset] = 0;

			if (chunk_hex[0] != 0)
			{
				chunk_size = (int)string_utility::hex_to_int64(chunk_hex);
				looking_for_chunk_header = false;
			}

			free(chunk_hex);
			data->remove_range(0, offset + 2);
		}

		if (looking_for_chunk_header == false)
		{
			int bytes_to_get = min(chunk_size, (int)data->count());
			if (bytes_to_get != chunk_size)
			{
				continue;
			}
			if (file != NULL)
			{
				fwrite(data->get_all(), 1, bytes_to_get, file);
			}

			bytes_written += data->count();
			debug_utility::debug_print("Written %lld bytes of unknown bytes\n", bytes_written);

			data->remove_range(0, bytes_to_get);
			looking_for_chunk_header = true;
		}
    }

	fclose(file);
	free(read_buffer);
}

void client::download(br_sslio_context io_context, data_store* data, const char* file_path, int64_t content_length)
{
	unsigned char* read_buffer = (unsigned char*)malloc(READ_BUFFER_SIZE);

	FILE* file = fopen(file_path, "wb");

	int64_t bytes_written = 0;
    while (true)
    {
        int bytes_read = br_sslio_read(&io_context, read_buffer,READ_BUFFER_SIZE);
		if (bytes_read < 0) 
		{
			break;
		}

		data->add_range(read_buffer, 0, bytes_read);
		if (file != NULL)
		{
			fwrite(data->get_all(), 1, data->count(), file);
		}

		bytes_written += data->count();
		debug_utility::debug_print("Written %lld bytes of ", bytes_written);
		debug_utility::debug_print("%lld bytes\n", content_length);
		data->remove_range(0, data->count());
    }

	fclose(file);
	free(read_buffer);
}