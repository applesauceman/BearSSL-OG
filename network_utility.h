#pragma once

#include <stdint.h>

class network_utility
{
public:
	static bool init();
	static bool is_ready();
	static bool wait_ready();
	static uint32_t resolve_host(const char* host);
};
