#include "stdafx.h"

#include "network_utility.h"
#include "client.h"
#include "server.h"
#include "debug_utility.h"
#include "data_store.h"

bool mount_e_drive()
{
	char* mountPoint = "\\??\\E:";
	char* systemPath = "\\Device\\Harddisk0\\Partition1";
	STRING sMountPoint = {(USHORT)strlen(mountPoint), (USHORT)strlen(mountPoint) + 1, mountPoint};
	STRING sSystemPath = {(USHORT)strlen(systemPath), (USHORT)strlen(systemPath) + 1, systemPath};
	int result = IoCreateSymbolicLink(&sMountPoint, &sSystemPath);
	return result == 0;
}

void __cdecl main()
{
	if (network_utility::init() == false)
	{
		return;
	}

	if (network_utility::wait_ready() == false)
	{
		return;
	}

	mount_e_drive();

	//const char* url = "https://codeload.github.com/Team-Resurgent/PrometheOS-Firmware/archive/refs/tags/V1.5.0.zip;
	const char* url = "https://codeload.github.com/Team-Resurgent/PrometheOS-Firmware/zip/refs/tags/V1.5.0";
	const char* file_path = "E:\\testfile.bin";

	while (true) 
	{
		client::download_file(url, file_path);
		Sleep(30000);
	}
}


