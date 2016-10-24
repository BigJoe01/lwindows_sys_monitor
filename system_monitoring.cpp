/*
    Released under Public Domain, Jozsef Oszlanczi, 2009
*/

#include "system_monitoring.h"

#define monsetTableDataN(ANAME,AVALUE) lua_pushstring(l,ANAME); \
	lua_pushnumber(l,AVALUE); \
	lua_settable(l,-3)

#define monsetTableDataS(ANAME,AVALUE) lua_pushstring(l,ANAME); \
	lua_pushstring(l,(const char*) AVALUE); \
	lua_settable(l,-3)

#define monsetTableDataLI(ANAME,AVALUE) lua_pushstring(l,ANAME); \
	sprintf(todouble,"%llu",AVALUE); \
	lua_pushstring(l,todouble); \
	lua_settable(l,-3)


double boot_time()
{
  double  uptime;
  time_t pt;
  FILETIME fileTime;
  long long ll;

  GetSystemTimeAsFileTime(&fileTime);

  ll = (((LONGLONG)(fileTime.dwHighDateTime)) << 32) \
    + fileTime.dwLowDateTime;
  pt = (time_t)((ll - 116444736000000000ull) / 10000000ull);

  uptime = GetTickCount() / 1000.00f;
  return (double)pt - uptime;
}

/******************************************************************************/
// Get Boot time
// Parameters -
// Result     - number, seconds
/********************************************************************************/
static int monitoring_boot_time(lua_State *l)
{   
  lua_pushnumber(l, (double)boot_time());
  return 1;
}

int cpu_count_logical()
{
  SYSTEM_INFO system_info;
  system_info.dwNumberOfProcessors = 0;

  GetSystemInfo(&system_info);
  if (system_info.dwNumberOfProcessors == 0) {
    return 0;
  }
  else {
    return system_info.dwNumberOfProcessors;
  }

}

/******************************************************************************/
// Get logical cpu count
// Parameters -
// Result     - number
/********************************************************************************/
static int monitoring_cpu_count_logical(lua_State *l)
{
  lua_pushinteger(l, cpu_count_logical());
	return 1;
}

typedef BOOL (WINAPI *LPFN_GLPI) (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION,PDWORD);

int cpu_count_phys()
{
  LPFN_GLPI glpi;
  DWORD rc;
  PSYSTEM_LOGICAL_PROCESSOR_INFORMATION buffer = NULL;
  PSYSTEM_LOGICAL_PROCESSOR_INFORMATION ptr = NULL;
  DWORD length = 0;
  DWORD offset = 0;
  int ncpus = 0;

  glpi = (LPFN_GLPI)GetProcAddress(GetModuleHandle(TEXT("kernel32")),
    "GetLogicalProcessorInformation");
  if (glpi == NULL)
    goto return_none;

  while (1) {
    rc = glpi(buffer, &length);
    if (rc == FALSE) {
      if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        if (buffer)
          free(buffer);
        buffer = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION)malloc(
          length);
        if (NULL == buffer) {
          return 0;
        }
      }
      else {
        goto return_none;
      }
    }
    else {
      break;
    }
  }

  ptr = buffer;
  while (offset + sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION) <= length) {
    if (ptr->Relationship == RelationProcessorCore)
      ncpus += 1;
    offset += sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
    ptr++;
  }

  free(buffer);
  if (ncpus == 0)
    goto return_none;
  else
  {
    return ncpus;
  }

return_none:
  if (buffer != NULL)
    free(buffer);
 return 0;

}


/******************************************************************************/
// Get physical cpu count
// Parameters -
// Result     - number
/********************************************************************************/

static int monitoring_cpu_count_phys(lua_State *l)
{    
  lua_pushinteger(l, cpu_count_phys());
	return 1;
}

#define LO_T ((float)1e-7)
#define HI_T (LO_T*4294967296.0)

void cpu_times(long pid,float& aidle, float& auser, float& akernel)
{
  float idle, kernel, user, system = 0;
  FILETIME idle_time, kernel_time, user_time;

  if (!GetSystemTimes(&idle_time, &kernel_time, &user_time)) {
     idle = 0;
     user = 0;
     system = 0;
     return;
  }

  idle = (float)((HI_T * idle_time.dwHighDateTime) + \
    (LO_T * idle_time.dwLowDateTime));
  user = (float)((HI_T * user_time.dwHighDateTime) + \
    (LO_T * user_time.dwLowDateTime));
  kernel = (float)((HI_T * kernel_time.dwHighDateTime) + \
    (LO_T * kernel_time.dwLowDateTime));

  // Kernel time includes idle time.
  // We return only busy kernel time subtracting idle time from
  // kernel time.
  system = (kernel - idle);
  aidle = idle;
  auser = user;
  akernel = kernel;
}

/******************************************************************************/
// Get cpu times
// Parameters -
// Result     - number
// Retrieves system CPU timing information as a (user, system, idle)
// tuple. On a multiprocessor system, the values returned are the
// sum of the designated times across all processors.
/********************************************************************************/

static int
monitoring_cpu_times(lua_State *l)
{
  float idle, user, system = 0;
  cpu_times(0,idle,user,system);
  
	lua_pushnumber(l,user);
	lua_pushnumber(l,system);
	lua_pushnumber(l,idle);
	return 3;
}

typedef struct _DISK_PERFORMANCE_WIN_2008 {
	LARGE_INTEGER BytesRead;
	LARGE_INTEGER BytesWritten;
	LARGE_INTEGER ReadTime;
	LARGE_INTEGER WriteTime;
	LARGE_INTEGER IdleTime;
	DWORD         ReadCount;
	DWORD         WriteCount;
	DWORD         QueueDepth;
	DWORD         SplitCount;
	LARGE_INTEGER QueryTime;
	DWORD         StorageDeviceNumber;
	WCHAR         StorageManagerName[8];
} DISK_PERFORMANCE_WIN_2008;


/******************************************************************************/
// Get disk io information
// Parameters - drive number 0-32
// Return table with hash code
/********************************************************************************/

/******************************************************************************/
// Get disk io information
// Parameters -
// Return 
/********************************************************************************/
static int
monitoring_disk_io_counters(lua_State *l)
{
    DISK_PERFORMANCE_WIN_2008 diskPerformance;
    DWORD dwSize;
    HANDLE hDevice = NULL;
    char szDevice[MAX_PATH];
    char szDeviceDisplay[MAX_PATH];
    char todouble[32];

	int devNum =    luaL_checkint(l,-1);
    if (devNum < 0 || devNum >32) {
		lua_pushnil(l);
		return 1;
	}
        sprintf(szDevice, "\\\\.\\PhysicalDrive%d", devNum);
        hDevice = CreateFile(szDevice, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

        if (hDevice == INVALID_HANDLE_VALUE)
		{
			lua_pushnil(l);
			return 1; 
        }
        if (DeviceIoControl(hDevice, IOCTL_DISK_PERFORMANCE, NULL, 0,&diskPerformance, sizeof(diskPerformance),&dwSize, NULL))
        {
			sprintf(szDeviceDisplay, "PhysicalDrive%d", devNum);
			lua_createtable(l,0,7);
			monsetTableDataS("Device",szDeviceDisplay);
			monsetTableDataN("ReadCount",diskPerformance.ReadCount);
			monsetTableDataN("WriteCount",diskPerformance.WriteCount);
			monsetTableDataLI("BytesRead",diskPerformance.BytesRead);
			monsetTableDataLI("BytesWritten",diskPerformance.BytesWritten);
			monsetTableDataLI("ReadTime",(diskPerformance.ReadTime.QuadPart * 10) / 1000);
			monsetTableDataLI("WriteTime",(diskPerformance.WriteTime.QuadPart * 10) / 1000);
			if (hDevice != NULL)
				CloseHandle(hDevice);
			return 1;
        };

    if (hDevice != NULL)
        CloseHandle(hDevice);
	lua_pushnil(l);
    return 1;
}

#ifndef _ARRAYSIZE
#define _ARRAYSIZE(a) (sizeof(a)/sizeof(a[0]))
#endif

static char *monitoring_get_drive_type(int type)
{
	switch (type) {
	case DRIVE_FIXED:
		return "fixed";
	case DRIVE_CDROM:
		return "cdrom";
	case DRIVE_REMOVABLE:
		return "removable";
	case DRIVE_UNKNOWN:
		return "unknown";
	case DRIVE_NO_ROOT_DIR:
		return "unmounted";
	case DRIVE_REMOTE:
		return "remote";
	case DRIVE_RAMDISK:
		return "ramdisk";
	default:
		return "?";
	}
}

/******************************************************************************/
// Get disk partitions
// Parameters - all?
// Return table with partition parameters
/********************************************************************************/

static int
monitoring_disk_partitions(lua_State *l)
{
    DWORD num_bytes;
    char drive_strings[255];
    char *drive_letter = drive_strings;
    int all = lua_toboolean(l,-1);
    int type;
    int ret;
    char opts[50];
    LPTSTR fs_type[MAX_PATH + 1] = { 0 };
    DWORD pflags = 0;

    SetErrorMode(SEM_FAILCRITICALERRORS);

    num_bytes = GetLogicalDriveStrings(254, drive_letter);
  
    if (num_bytes == 0) {
       lua_pushnil(l);
	   return 1;
    }

	lua_newtable(l); 

    while (*drive_letter != 0) {
        opts[0] = 0;
        fs_type[0] = 0;

        type = GetDriveType(drive_letter);
        
        // by default we only show hard drives and cd-roms
        if (all == 0) {
            if ((type == DRIVE_UNKNOWN) ||
                    (type == DRIVE_NO_ROOT_DIR) ||
                    (type == DRIVE_REMOTE) ||
                    (type == DRIVE_RAMDISK)) {
                goto next;
            }
            // floppy disk: skip it by default as it introduces a
            // considerable slowdown.
            if ((type == DRIVE_REMOVABLE) &&
                    (strcmp(drive_letter, "A:\\")  == 0)) {
                goto next;
            }
        }

        ret = GetVolumeInformation( (LPCTSTR)drive_letter, NULL, _ARRAYSIZE(drive_letter), NULL, NULL, &pflags, (LPTSTR)fs_type, _ARRAYSIZE(fs_type));
        if (ret == 0) {
            // We might get here in case of a floppy hard drive, in
            // which case the error is (21, "device not ready").
            // Let's pretend it didn't happen as we already have
            // the drive name and type ('removable').
            strcat(opts, "");
            SetLastError(0);
        }
        else {
            if (pflags & FILE_READ_ONLY_VOLUME) {
                strcat(opts, "ro");
            }
            else {
                strcat(opts, "rw");
            }
            if (pflags & FILE_VOLUME_IS_COMPRESSED) {
                strcat(opts, ",compressed");
            }
        }

        if (strlen(opts) > 0) {
            strcat(opts, ",");
        }
        strcat(opts, monitoring_get_drive_type(type));

		monsetTableDataS(drive_letter,opts);
		goto next;

next:
        drive_letter = strchr(drive_letter, 0) + 1;
    }

    SetErrorMode(0);
	return 1;
}

/******************************************************************************/
// Get disk usage
// Parameters - string path
// Return table with partition parameters
/********************************************************************************/

static int monitoring_disk_usage(lua_State *l)
{
	BOOL retval;
	ULARGE_INTEGER allforu, total, free;
	std::string path = luaL_checkstring(l,-1);
	char todouble[32];
	retval = GetDiskFreeSpaceExA((LPCSTR)path.c_str(), &allforu, &total, &free);
	if (retval) {
		sprintf(todouble,"%llu",allforu);
		lua_pushstring(l,todouble);
		sprintf(todouble,"%llu",total);
		lua_pushstring(l,todouble);
		sprintf(todouble,"%llu",free);
		lua_pushstring(l,todouble);
	}
	else
	{
		lua_pushnil(l);
		lua_pushnil(l);
		lua_pushnil(l);
	}
	return 3;
}

/******************************************************************************/
// Check selected process is running
// Parameters - process id
// Return  -1 - 1
/********************************************************************************/
int
	monitoring_pid_is_running(DWORD pid)
{
	HANDLE hProcess;
	DWORD exitCode;

	// Special case for PID 0 System Idle Process
	if (pid == 0) {
		return 1;
	}

	if (pid < 0) {
		return 0;
	}

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
		FALSE, pid);
	if (NULL == hProcess) {
		// invalid parameter is no such process
		if (GetLastError() == ERROR_INVALID_PARAMETER) {
			CloseHandle(hProcess);
			return 0;
		}

		// access denied obviously means there's a process to deny access to...
		if (GetLastError() == ERROR_ACCESS_DENIED) {
			CloseHandle(hProcess);
			return 1;
		}

		CloseHandle(hProcess);
		return -1;
	}

	if (GetExitCodeProcess(hProcess, &exitCode)) {
		CloseHandle(hProcess);
		return (exitCode == STILL_ACTIVE);
	}

	// access denied means there's a process there so we'll assume
	// it's running
	if (GetLastError() == ERROR_ACCESS_DENIED) {
		CloseHandle(hProcess);
		return 1;
	}

	CloseHandle(hProcess);
	return -1;
}

/******************************************************************************/
// Return a list of network connections opened by a process
// Parameters - 
// Return   host,port
/********************************************************************************/
#ifndef _IPRTRMIB_H
typedef struct _MIB_TCP6ROW_OWNER_PID {
	UCHAR ucLocalAddr[16];
	DWORD dwLocalScopeId;
	DWORD dwLocalPort;
	UCHAR ucRemoteAddr[16];
	DWORD dwRemoteScopeId;
	DWORD dwRemotePort;
	DWORD dwState;
	DWORD dwOwningPid;
} MIB_TCP6ROW_OWNER_PID, *PMIB_TCP6ROW_OWNER_PID;

typedef struct _MIB_TCP6TABLE_OWNER_PID {
	DWORD dwNumEntries;
	MIB_TCP6ROW_OWNER_PID table[ANY_SIZE];
} MIB_TCP6TABLE_OWNER_PID, *PMIB_TCP6TABLE_OWNER_PID;
#endif

#ifndef __IPHLPAPI_H__
typedef struct in6_addr {
	union {
		UCHAR Byte[16];
		USHORT Word[8];
	} u;
} IN6_ADDR, *PIN6_ADDR, FAR *LPIN6_ADDR;

typedef enum _UDP_TABLE_CLASS {
	UDP_TABLE_BASIC,
	UDP_TABLE_OWNER_PID,
	UDP_TABLE_OWNER_MODULE
} UDP_TABLE_CLASS, *PUDP_TABLE_CLASS;

typedef struct _MIB_UDPROW_OWNER_PID {
	DWORD dwLocalAddr;
	DWORD dwLocalPort;
	DWORD dwOwningPid;
} MIB_UDPROW_OWNER_PID, *PMIB_UDPROW_OWNER_PID;

typedef struct _MIB_UDPTABLE_OWNER_PID {
	DWORD dwNumEntries;
	MIB_UDPROW_OWNER_PID table[ANY_SIZE];
} MIB_UDPTABLE_OWNER_PID, *PMIB_UDPTABLE_OWNER_PID;
#endif

typedef struct _MIB_UDP6ROW_OWNER_PID {
	UCHAR ucLocalAddr[16];
	DWORD dwLocalScopeId;
	DWORD dwLocalPort;
	DWORD dwOwningPid;
} MIB_UDP6ROW_OWNER_PID, *PMIB_UDP6ROW_OWNER_PID;

typedef struct _MIB_UDP6TABLE_OWNER_PID {
	DWORD dwNumEntries;
	MIB_UDP6ROW_OWNER_PID table[ANY_SIZE];
} MIB_UDP6TABLE_OWNER_PID, *PMIB_UDP6TABLE_OWNER_PID;


#define BYTESWAP_USHORT(x) ((((USHORT)(x) << 8) | ((USHORT)(x) >> 8)) & 0xffff)

#ifndef AF_INET6
#define AF_INET6 23
#endif

// a signaler for connections without an actual status
static int PSUTIL_CONN_NONE = 128;


const char* net_connection_status[] = {
      "NONE",	 
	  "STATE_CLOSED",
	  "STATE_LISTEN",
	  "STATE_SYN_SENT",
	  "STATE_SYN_RCVD",
	  "STATE_ESTAB",
	  "STATE_FIN_WAIT1",
	  "STATE_FIN_WAIT2",
	  "STATE_CLOSE_WAIT",
	  "STATE_CLOSING",
	  "STATE_LAST_ACK",
	  "STATE_TIME_WAIT",
	  "STATE_DELETE_TCB"
}; 

static int monitoring_net_connections(lua_State *l)
{
    static long null_address[4] = { 0, 0, 0, 0 };

  
	unsigned long pid = luaL_checkint(l,-3);
    const char*   streamtype = luaL_checkstring(l,-2);
	const char*   protocol   = luaL_checkstring(l,-1);
	int           counter;

	if (protocol == NULL || streamtype == NULL )
	{
		lua_pushnil(l);
		return 1;
	}


	if (!( strcmp(streamtype,"inet4") == 0 || strcmp(streamtype,"inet6") == 0 ))
	{
		lua_pushnil(l);
		return 1;
	}

	if (!( strcmp(protocol,"tcp") == 0 || strcmp(protocol,"udp") == 0 ))
	{
		lua_pushnil(l);
		return 1;
	}


	if (pid != -1) {
		if (monitoring_pid_is_running(pid) == 0) {
			lua_pushnil(l);
			return 1;
		}
	}

    typedef PSTR (NTAPI * _RtlIpv4AddressToStringA)(struct in_addr *, PSTR);
    typedef PSTR (NTAPI * _RtlIpv6AddressToStringA)(struct in6_addr *, PSTR);
    typedef DWORD (WINAPI * _GetExtendedTcpTable)(PVOID, PDWORD, BOOL, ULONG,TCP_TABLE_CLASS, ULONG);
    typedef DWORD (WINAPI * _GetExtendedUdpTable)(PVOID, PDWORD, BOOL, ULONG,UDP_TABLE_CLASS, ULONG);

	_RtlIpv4AddressToStringA		rtlIpv4AddressToStringA;
	_RtlIpv6AddressToStringA		rtlIpv6AddressToStringA;
	_GetExtendedTcpTable			getExtendedTcpTable;

	_GetExtendedUdpTable			getExtendedUdpTable;
    PVOID							table = NULL;
    DWORD							tableSize;
    PMIB_TCPTABLE_OWNER_PID			tcp4Table;
    PMIB_UDPTABLE_OWNER_PID			udp4Table;
    PMIB_TCP6TABLE_OWNER_PID		tcp6Table;
    PMIB_UDP6TABLE_OWNER_PID		udp6Table;
    ULONG							i;
    CHAR							addressBufferLocal[65];
    CHAR							addressBufferRemote[65];
    
    
    {
        HMODULE ntdll;
        HMODULE iphlpapi;

        ntdll = LoadLibrary(TEXT("ntdll.dll"));
        rtlIpv4AddressToStringA = (_RtlIpv4AddressToStringA)GetProcAddress(ntdll, "RtlIpv4AddressToStringA");
        rtlIpv6AddressToStringA = (_RtlIpv6AddressToStringA)GetProcAddress(ntdll, "RtlIpv6AddressToStringA");
        /* TODO: Check these two function pointers */

        iphlpapi = LoadLibrary(TEXT("iphlpapi.dll"));
        getExtendedTcpTable = (_GetExtendedTcpTable)GetProcAddress(iphlpapi,"GetExtendedTcpTable");
        getExtendedUdpTable = (_GetExtendedUdpTable)GetProcAddress(iphlpapi,"GetExtendedUdpTable");
        FreeLibrary(ntdll);
        FreeLibrary(iphlpapi);
    }


	if ((getExtendedTcpTable == NULL) || (getExtendedUdpTable == NULL)) {
        lua_pushnil(l);
        return 1;
    }

    // TCP IPv4 -------------------------------------------------------
    if ( strcmp(streamtype,"inet4") == 0 &&  strcmp(protocol,"tcp") == 0)
    {
        table = NULL;
       
        tableSize = 0;
        getExtendedTcpTable(NULL, &tableSize, FALSE, AF_INET,TCP_TABLE_OWNER_PID_ALL, 0);

        table = malloc(tableSize);
        if (table == NULL) {
            lua_pushnil(l);
			return 1;
        }
  
		counter = 0;
		lua_newtable(l);
		if (getExtendedTcpTable(table, &tableSize, FALSE, AF_INET,TCP_TABLE_OWNER_PID_ALL, 0) == 0)
        {
            tcp4Table = (PMIB_TCPTABLE_OWNER_PID)table;
			
            for (i = 0; i < tcp4Table->dwNumEntries; i++)
            {
                if (pid != -1) {
                    if (tcp4Table->table[i].dwOwningPid != pid) {
                        continue;
                    }
                }
				++counter;
				lua_pushnumber(l,counter);
				lua_newtable(l);
                if (tcp4Table->table[i].dwLocalAddr != 0 ||tcp4Table->table[i].dwLocalPort != 0)
                {
					

					   struct in_addr addr;

						addr.S_un.S_addr = tcp4Table->table[i].dwLocalAddr;
						rtlIpv4AddressToStringA(&addr, addressBufferLocal);
						
						monsetTableDataS("address",addressBufferLocal);
						monsetTableDataN("port",BYTESWAP_USHORT(tcp4Table->table[i].dwLocalPort));
				}		

					// On Windows <= XP, remote addr is filled even if socket
					// is in LISTEN mode in which case we just ignore it.
					if ((tcp4Table->table[i].dwRemoteAddr != 0 ||
							tcp4Table->table[i].dwRemotePort != 0) &&
							(tcp4Table->table[i].dwState != MIB_TCP_STATE_LISTEN))
					{
						struct in_addr addr;

						addr.S_un.S_addr = tcp4Table->table[i].dwRemoteAddr;
						rtlIpv4AddressToStringA(&addr, addressBufferRemote);
						monsetTableDataS("remote_address",addressBufferRemote);
						monsetTableDataN("remote_port",BYTESWAP_USHORT(tcp4Table->table[i].dwRemotePort));
						monsetTableDataS("protocol","tcp");
						monsetTableDataS("type","inet4");
						monsetTableDataN("pid",tcp4Table->table[i].dwOwningPid);
						monsetTableDataS("status",net_connection_status[tcp4Table->table[i].dwState]);
						monsetTableDataN("status_number",tcp4Table->table[i].dwState);
                   }
				
			lua_settable(l,-3);			
         }
	    }
		free(table);
		return 1;
    }
	// TCP IPv4 -------------------------------------------------------
    // TCP IPv6

    if ( strcmp(streamtype,"inet6") == 0 &&  strcmp(protocol,"tcp") == 0)
    {
        table = NULL;
        tableSize = 0;
        getExtendedTcpTable(NULL, &tableSize, FALSE, AF_INET6,TCP_TABLE_OWNER_PID_ALL, 0);

        table = malloc(tableSize);
        if (table == NULL) {
           lua_pushnil(l);
		   return 1;
        }
		
		lua_newtable(l);
		counter = 0;
        if (getExtendedTcpTable(table, &tableSize, FALSE, AF_INET6,TCP_TABLE_OWNER_PID_ALL, 0) == 0)
        {
            tcp6Table = (PMIB_TCP6TABLE_OWNER_PID)table;
			
            for (i = 0; i < tcp6Table->dwNumEntries; i++)
            {
                if (pid != -1) {
                    if (tcp6Table->table[i].dwOwningPid != pid) {
                        continue;
                    }
                }
				++counter;
				lua_pushnumber(l,counter);
				lua_newtable(l);

                if (memcmp(tcp6Table->table[i].ucLocalAddr, null_address, 16)!= 0 || tcp6Table->table[i].dwLocalPort != 0)
                {
                    struct in6_addr addr;

                    memcpy(&addr, tcp6Table->table[i].ucLocalAddr, 16);
                    rtlIpv6AddressToStringA(&addr, addressBufferLocal);
					monsetTableDataS("address",addressBufferLocal);
					monsetTableDataN("port",BYTESWAP_USHORT(tcp6Table->table[i].dwLocalPort));
					
                };

                // On Windows <= XP, remote addr is filled even if socket
                // is in LISTEN mode in which case we just ignore it.
                if ((memcmp(tcp6Table->table[i].ucRemoteAddr, null_address, 16) != 0 ||  tcp6Table->table[i].dwRemotePort != 0) &&
                      (tcp6Table->table[i].dwState != MIB_TCP_STATE_LISTEN))
                {
                    struct in6_addr addr;

                    memcpy(&addr, tcp6Table->table[i].ucRemoteAddr, 16);
                    rtlIpv6AddressToStringA(&addr, addressBufferRemote);
                    
					monsetTableDataS("remote_address",addressBufferRemote);
					monsetTableDataN("remote_port",BYTESWAP_USHORT(tcp6Table->table[i].dwRemotePort));
					monsetTableDataS("protocol","tcp");
					monsetTableDataS("type","inet6");
					monsetTableDataN("pid",tcp6Table->table[i].dwOwningPid);
					monsetTableDataS("status",net_connection_status[tcp6Table->table[i].dwState]);
					monsetTableDataN("status_number",tcp6Table->table[i].dwState);

               }

               lua_settable(l,-3);
			}	 
 		}
        free(table);
		return 1;
    }

    // UDP IPv4

    if ( strcmp(streamtype,"inet4") == 0 &&  strcmp(protocol,"udp") == 0)
    {
        table = NULL;
        tableSize = 0;
        getExtendedUdpTable(NULL, &tableSize, FALSE, AF_INET,UDP_TABLE_OWNER_PID, 0);

        table = malloc(tableSize);
        if (table == NULL) {
           lua_pushnil(l);
		   return 1;
		}

		counter = 0;
		lua_newtable(l);
        if (getExtendedUdpTable(table, &tableSize, FALSE, AF_INET,UDP_TABLE_OWNER_PID, 0) == 0)
        {
            udp4Table = (PMIB_UDPTABLE_OWNER_PID)table;
			
			for (i = 0; i < udp4Table->dwNumEntries; i++)
            {
				
                if (pid != -1) {
                    if (udp4Table->table[i].dwOwningPid != pid) {
                        continue;
                    }
                }
				++counter;
				lua_pushnumber(l,counter);
				lua_newtable(l);

				if (udp4Table->table[i].dwLocalAddr != 0 ||udp4Table->table[i].dwLocalPort != 0)
				{
					struct in_addr addr;

					addr.S_un.S_addr = udp4Table->table[i].dwLocalAddr;
					rtlIpv4AddressToStringA(&addr, addressBufferLocal);
					
					monsetTableDataS("address",addressBufferLocal);
					monsetTableDataN("port",BYTESWAP_USHORT(udp4Table->table[i].dwLocalPort));

					monsetTableDataS("protocol","udp");
					monsetTableDataS("type","inet4");
					monsetTableDataN("pid",udp4Table->table[i].dwOwningPid);
		        }
               lua_settable(l,-3);
			}
			
		}
        free(table);
		return 1;
    }

    // UDP IPv6
	if ( strcmp(streamtype,"inet6") == 0 &&  strcmp(protocol,"udp") == 0)
	{
        table = NULL;
        tableSize = 0;
        getExtendedUdpTable(NULL, &tableSize, FALSE,AF_INET6, UDP_TABLE_OWNER_PID, 0);

        table = malloc(tableSize);
        if (table == NULL) {
           lua_pushnil(l);
		   return 1;
        }
		counter = 0;
		lua_newtable(l);
        if (getExtendedUdpTable(table, &tableSize, FALSE, AF_INET6,UDP_TABLE_OWNER_PID, 0) == 0)
        {
            udp6Table = (PMIB_UDP6TABLE_OWNER_PID)table;
			
            for (i = 0; i < udp6Table->dwNumEntries; i++)
            {
                if (pid != -1) {
                    if (udp6Table->table[i].dwOwningPid != pid) {
                        continue;
                    }
                }
				++counter;
				lua_pushnumber(l,counter);
				lua_newtable(l);

                if (memcmp(udp6Table->table[i].ucLocalAddr, null_address, 16)!= 0 || udp6Table->table[i].dwLocalPort != 0)
                {
                    struct in6_addr addr;

                    memcpy(&addr, udp6Table->table[i].ucLocalAddr, 16);
                    rtlIpv6AddressToStringA(&addr, addressBufferLocal);
                   
					monsetTableDataS("address",addressBufferLocal);
					monsetTableDataN("port",BYTESWAP_USHORT(udp6Table->table[i].dwLocalPort));

					monsetTableDataS("protocol","udp");
					monsetTableDataS("type","inet6");
					monsetTableDataN("pid",udp6Table->table[i].dwOwningPid);

               }
			   lua_settable(l,-3);
           }
		 }
         free(table);
		 return 1;
     }

    lua_pushnil(l);
    return 1;
 }
 

 /******************************************************************************/
 // Return a Network io counters
 // Parameters - 
 // Return   tables list with adapter info
 /********************************************************************************/

static int
monitoring_net_io_counters(lua_State *l){
    int attempts = 0;
    ULONG outBufLen = 15000;
    char ifname[MAX_PATH];
    DWORD dwRetVal = 0;
    MIB_IFROW *pIfRow = NULL;
    ULONG flags = 0;
    ULONG family = AF_UNSPEC;
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;

    do {
        pAddresses = (IP_ADAPTER_ADDRESSES *) malloc(outBufLen);
        if (pAddresses == NULL) {
            lua_pushnil(l);
			return 1;
        }

        dwRetVal = GetAdaptersAddresses(family, flags, NULL, pAddresses,&outBufLen);
        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            free(pAddresses);
            pAddresses = NULL;
        }
        else {
            break;
        }

        attempts++;
    } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (attempts < 3));

    if (dwRetVal != NO_ERROR) {
        lua_pushnil(l);
        return 1;
    }


	lua_newtable(l);
	int counter = 0;
    pCurrAddresses = pAddresses;
    while (pCurrAddresses) {
        pIfRow = (MIB_IFROW *) malloc(sizeof(MIB_IFROW));

        pIfRow->dwIndex = pCurrAddresses->IfIndex;
        dwRetVal = GetIfEntry(pIfRow);
        
		if (dwRetVal == NO_ERROR) {
			++counter;
			lua_pushnumber(l,counter);
			lua_newtable(l);
			
			sprintf(ifname, "%wS", pCurrAddresses->FriendlyName);
			monsetTableDataS("FriendlyName",ifname);
			monsetTableDataN("OutOctets",pIfRow->dwOutOctets);
			monsetTableDataN("InOctets",pIfRow->dwInOctets);
			monsetTableDataN("OutUCastPackets",pIfRow->dwOutUcastPkts);
			monsetTableDataN("InUCastPackets",pIfRow->dwInUcastPkts);
			monsetTableDataN("InErrors",pIfRow->dwInErrors);
			monsetTableDataN("OutErrors",pIfRow->dwOutErrors);
			monsetTableDataN("InDiscards",pIfRow->dwInDiscards);
			monsetTableDataN("OutDiscards",pIfRow->dwOutDiscards);
		    
			lua_settable(l,-3);
		}

		
		free(pIfRow);
		pIfRow = NULL;
        pCurrAddresses = pCurrAddresses->Next;
    }


	
	if (pAddresses != NULL) free(pAddresses);
    if (pIfRow != NULL) free(pIfRow);

    return 1;
}

/******************************************************************************/
// Return all cpu performance
// Parameters - 
// Return  
/********************************************************************************/

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION {
	LARGE_INTEGER IdleTime;
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER Reserved1[2];
	ULONG Reserved2;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION,
	*PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

static int
monitoring_per_cpu_times(lua_State *l)
{
    float idle, kernel, user;
    typedef DWORD (_stdcall * NTQSI_PROC) (int, PVOID, ULONG, PULONG);
    NTQSI_PROC NtQuerySystemInformation;
    HINSTANCE hNtDll;
    SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION *sppi = NULL;
    SYSTEM_INFO si;
    UINT i;
   
	int counter = 0;
	 lua_newtable(l);

    // dynamic linking is mandatory to use NtQuerySystemInformation
    hNtDll = LoadLibrary(TEXT("ntdll.dll"));
    if (hNtDll != NULL) {
        // gets NtQuerySystemInformation address
        NtQuerySystemInformation = (NTQSI_PROC)GetProcAddress(hNtDll, "NtQuerySystemInformation");

        if (NtQuerySystemInformation != NULL)
        {
            // retrives number of processors
            GetSystemInfo(&si);

            // allocates an array of SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
            // structures, one per processor
            sppi = (SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION *) malloc(si.dwNumberOfProcessors * sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION));
            if (sppi != NULL)
            {
                // gets cpu time informations
                if (0 == NtQuerySystemInformation(SystemProcessorPerformanceInformation,sppi,si.dwNumberOfProcessors * sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION),NULL))
                {
                    // computes system global times summing each
                    // processor value
				    idle = user = kernel = 0;
                    
					for (i = 0; i < si.dwNumberOfProcessors; i++) {
						++counter;
						lua_pushnumber(l,counter);
						lua_newtable(l);


						user = (float)((HI_T * sppi[i].UserTime.HighPart) +
                                       (LO_T * sppi[i].UserTime.LowPart));
                        idle = (float)((HI_T * sppi[i].IdleTime.HighPart) +
                                       (LO_T * sppi[i].IdleTime.LowPart));
                        kernel = (float)((HI_T * sppi[i].KernelTime.HighPart) +
                                         (LO_T * sppi[i].KernelTime.LowPart));
                        // kernel time includes idle time on windows
                        // we return only busy kernel time subtracting
                        // idle time from kernel time
						monsetTableDataN("user",user);
						monsetTableDataN("kernel",kernel - idle);
						monsetTableDataN("idle",idle);
                  
					  lua_settable(l,-3);						 
					}
                    
					
                }  // END NtQuerySystemInformation
            }  // END malloc SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
        }  // END GetProcAddress
    }  // END LoadLibrary

    if (sppi) {
        free(sppi);
    }
    if (hNtDll) {
        FreeLibrary(hNtDll);
    }
    return 1;
} 




/******************************************************************************/
// Return all memory information
// Parameters - 
// Return  map table with values
/********************************************************************************/
static int
monitoring_virtual_mem(lua_State *l)
{
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);

    if (! GlobalMemoryStatusEx(&memInfo) ) {
        lua_pushnil(l);
		return 1;
    }

	lua_newtable(l);
 
    monsetTableDataN("TotalPhysic",memInfo.ullTotalPhys);
	monsetTableDataN("AvaliablePhysic",memInfo.ullAvailPhys);
	monsetTableDataN("TotalPageFile",memInfo.ullTotalPageFile);
	monsetTableDataN("AvaliablePageFile",memInfo.ullAvailPageFile);
	monsetTableDataN("TotalVirtual",memInfo.ullTotalVirtual);
	monsetTableDataN("AvaliableVirtual",memInfo.ullAvailVirtual);

	return 1; 
}
   
const luaL_Reg monitoring_reg[] = {
	{"boot_time",monitoring_boot_time},
	{"cpu_logical",monitoring_cpu_count_logical},
	{"cpu_physic",monitoring_cpu_count_phys},
	{"cpu_times",monitoring_cpu_times},
	{"disk_io",monitoring_disk_io_counters},
	{"disk_partition",monitoring_disk_partitions},
	{"disk_usage",monitoring_disk_usage},
	{"net_connections",monitoring_net_connections},
	{"net_io",monitoring_net_io_counters},
	{"cpu_alltimes",monitoring_per_cpu_times},
	{"mem_status",monitoring_virtual_mem},
	{ NULL,NULL }
};

static const char* s_Monitoring_Name = "monitoring";

int luaopen_monitoring(lua_State* l){
	luaL_register(l,s_Monitoring_Name, monitoring_reg);
	lua_pushvalue(l, -1);
	lua_setglobal(l, s_Monitoring_Name);

	return 1;
}