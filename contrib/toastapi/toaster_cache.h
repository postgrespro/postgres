#ifndef TOASTERCACHE_H
#define TOASTERCACHE_H

#include "toastapi.h"

typedef struct ToasterCacheEntry
{
	Oid			toasterOid;
	TsrRoutine *routine;
} ToasterCacheEntry;

typedef struct ToastrelCacheEntry
{
	Oid 		relid;
	int16		attnum;
} ToastrelCacheEntry;

#endif
