#include "debug_utility.h"

#include <xtl.h>
#include <stdio.h>

int debug_utility::debug_print(const char* format, ...)
{
	va_list args;
    va_start(args, format);

	int length = _vsnprintf(NULL, 0, format, args);

	char* message = (char*)malloc(length + 1);
	_vsnprintf(message, length, format, args);
	message[length] = 0;

    va_end(args);

	OutputDebugStringA(message);
	free(message);
	return length;
}