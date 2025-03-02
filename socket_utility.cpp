#include "socket_utility.h"

#include <xtl.h>
#include <winsockx.h>
#include <stdint.h>

uint32_t socket_utility::connect_to_host(uint32_t host_ip, uint16_t port)
{
    sockaddr_in server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
	server_addr.sin_addr.S_un.S_addr = host_ip;

    uint32_t connect_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (connect_socket == INVALID_SOCKET) 
	{
        return -1;
    }

    if (connect(connect_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) 
	{
        return -1;
    }

	return connect_socket;
}

int socket_utility::socket_read(void *context, unsigned char *buffer, size_t length)
{
    while (true)
	{
        int socket = *(int *)context;
        int bytes_read = recv(socket, (char *)buffer, length, 0); 
        if (bytes_read == SOCKET_ERROR) 
		{
            if (WSAGetLastError() == WSAEINTR || WSAGetLastError() == WSAEWOULDBLOCK) 
			{
                continue;
            }
            return -1;
        }
        if (bytes_read == 0) 
		{
            return 0;
        }
        return bytes_read; 
    }
}

int socket_utility::socket_write(void *context, const unsigned char *buffer, size_t length)
{
    while (true)
	{
        int socket = *(int *)context;
        int bytes_written = send(socket, (const char *)buffer, length, 0); 
        if (bytes_written == SOCKET_ERROR) 
		{
            if (WSAGetLastError() == WSAEINTR || WSAGetLastError() == WSAEWOULDBLOCK) 
			{
                continue; 
            }
            return -1;
        }
        return bytes_written;
    }
}