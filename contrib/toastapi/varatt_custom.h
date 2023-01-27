#ifndef VARATT_CUSTOM_H
#define VARATT_CUSTOM_H

#include "postgres.h"
#include "varatt.h"

typedef struct uint32align16
{
	uint16	hi;
	uint16	lo;
} uint32align16;

#define set_uint32align16(p, v)	\
	( \
		(p)->hi = (v) >> 16, \
		(p)->lo = (v) & 0xffff \
	)

#define get_uint32align16(p)	\
	(((uint32)((p)->hi)) << 16 | ((uint32)((p)->lo)))

/* varatt_custom uses 16bit aligment */
typedef struct varatt_custom
{
	uint16			va_toasterdatalen;/* total size of toast pointer, < BLCKSZ */
	uint32align16	va_rawsize;		/* Original data size (includes header) */
	uint32align16	va_toasterid;	/* Toaster ID, actually Oid */
	char		va_toasterdata[FLEXIBLE_ARRAY_MEMBER];	/* Custom toaster data */
}			varatt_custom;

#define VARTAG_CUSTOM_SIZE(tag) \
	((tag) == VARTAG_CUSTOM ? offsetof(varatt_custom, va_toasterdata)	: \
	 (AssertMacro(false), 0))

/* Custom Toast pointer */
#define VARATT_CUSTOM_GET_TOASTPOINTER(PTR) \
	((varatt_custom *) VARDATA_EXTERNAL(PTR))

#define VARATT_CUSTOM_GET_TOASTERID(PTR) \
	(get_uint32align16(&VARATT_CUSTOM_GET_TOASTPOINTER(PTR)->va_toasterid))

#define VARATT_CUSTOM_SET_TOASTERID(PTR, V) \
	(set_uint32align16(&VARATT_CUSTOM_GET_TOASTPOINTER(PTR)->va_toasterid, (V)))

#define VARATT_CUSTOM_GET_DATA_RAW_SIZE(PTR) \
	(get_uint32align16(&VARATT_CUSTOM_GET_TOASTPOINTER(PTR)->va_rawsize))

#define VARATT_CUSTOM_SET_DATA_RAW_SIZE(PTR, V) \
	(set_uint32align16(&VARATT_CUSTOM_GET_TOASTPOINTER(PTR)->va_rawsize, (V)))

#define VARATT_CUSTOM_GET_DATA_SIZE(PTR) \
	((int32) VARATT_CUSTOM_GET_TOASTPOINTER(PTR)->va_toasterdatalen)

#define VARATT_CUSTOM_SET_DATA_SIZE(PTR, V) \
	(VARATT_CUSTOM_GET_TOASTPOINTER(PTR)->va_toasterdatalen = (V))

#define VARATT_CUSTOM_GET_DATA(PTR) \
	(VARATT_CUSTOM_GET_TOASTPOINTER(PTR)->va_toasterdata)

#define VARATT_CUSTOM_SIZE(datalen) \
	((Size) VARHDRSZ_EXTERNAL + offsetof(varatt_custom, va_toasterdata) + (datalen))

#define VARSIZE_CUSTOM(PTR)	VARATT_CUSTOM_SIZE(VARATT_CUSTOM_GET_DATA_SIZE(PTR))

#endif