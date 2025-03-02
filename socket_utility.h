#pragma once

#include <stdint.h>

class socket_utility
{
public:
	static uint32_t connect_to_host(uint32_t host_ip, uint16_t port);
	static int socket_read(void *context, unsigned char *buffer, size_t length);
	static int socket_write(void *context, const unsigned char *buffer, size_t length);
};
