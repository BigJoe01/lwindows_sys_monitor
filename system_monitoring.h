/*
	Released under Public Domain, Jozsef Oszlanczi, 2009
*/
#pragma once

extern "C"
{
	#include <lua.h>
	#include <lualib.h>
	#include <lauxlib.h>
	#include <luaconf.h>
	int luaopen_monitoring(lua_State* l);
}

 #define WIN32_LEAN_AND_MEAN
 #include <windows.h>
 #include <Psapi.h>
 #include <time.h>
 #include <lm.h>
 #include <WinIoCtl.h>
 #include <tchar.h>
 #include <tlhelp32.h>
 #include <winsock2.h>
 #include <iphlpapi.h>
 #include <wtsapi32.h>
 #include <stdlib.h>
 #include <cstdio>
 #include <string>	
 // Link with Iphlpapi.lib
 #pragma comment(lib, "IPHLPAPI.lib")
 #pragma comment(lib, "WS2_32.lib")

// --- system-related functions
static int monitoring_boot_time(lua_State *l);
static int monitoring_cpu_count_logical(lua_State *l);
static int monitoring_cpu_count_phys(lua_State *l);
static int monitoring_cpu_times(lua_State *l);
static int monitoring_disk_io_counters(lua_State *l);
static int monitoring_disk_partitions(lua_State *l);
static int monitoring_disk_usage(lua_State *l);
static int monitoring_net_connections(lua_State *l);
static int monitoring_net_io_counters(lua_State *l);
static int monitoring_per_cpu_times(lua_State *l);
static int monitoring_virtual_mem(lua_State *l);