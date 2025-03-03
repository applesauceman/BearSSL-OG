#pragma once

#include "pointer_vector.h"
#include "data_store.h"

#include <stdint.h>
#include <bearssl.h>

class client
{
public:
	static int download_file(const char* url, uint16_t port, const char* file_path);
private:
	static void populate_headers(br_sslio_context io_context, data_store* data, pointer_vector<char*>* headers);
	static void chunk_download(br_sslio_context io_context, data_store* data, const char* file_path);
	static void download(br_sslio_context io_context, data_store* data, const char* file_path, int64_t content_length);
};