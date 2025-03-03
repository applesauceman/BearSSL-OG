#pragma once

#include <xtl.h>
#include <stdint.h>

class server
{
public:
	void start(uint16_t port);
	void stop();
private:
	HANDLE thread;
};
