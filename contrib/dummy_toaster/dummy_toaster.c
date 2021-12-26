/*-------------------------------------------------------------------------
 *
 * dummy_toaster.c
 *		Dummy toaster utilities.
 *
 * Portions Copyright (c) 2016-2021, PostgreSQL Global Development Group
 * Portions Copyright (c) 1990-1993, Regents of the University of California
 *
 * IDENTIFICATION
 *	  contrib/dummy_toaster/dummy_toaster.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"
#include "fmgr.h"
#include "access/toasterapi.h"
#include "access/detoast.h"
#include "access/heaptoast.h"
#include "access/htup_details.h"
#include "catalog/pg_toaster.h"
#include "utils/builtins.h"
#include "utils/syscache.h"
#include "access/toast_compression.h"
#include "access/xact.h"
#include "catalog/binary_upgrade.h"
#include "catalog/catalog.h"
#include "catalog/dependency.h"
#include "catalog/heap.h"
#include "catalog/index.h"
#include "catalog/namespace.h"
#include "catalog/pg_am.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_opclass.h"
#include "catalog/pg_type.h"
#include "catalog/toasting.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "storage/lock.h"
#include "utils/rel.h"
#include "access/relation.h"
#include "access/table.h"
#include "access/toast_internals.h"
#include "access/heapam.h"

PG_MODULE_MAGIC;
PG_FUNCTION_INFO_V1(dummy_toaster_handler);
/*
Datum dummyToast (Relation toast_rel,
								Datum value,
								int max_inline_size);
Datum dummyDetoast (Relation toast_rel,
								Datum toast_ptr, Datum oldvalue,
								int offset, int length);
void * dummyGetVtable (Datum toast_ptr);
bool dummyToasterValidate (Oid toasteroid);
*/
typedef struct varatt_dummy_toaster
{
	varatt_external	toast_ptr;
	char *data_buffer;
} varatt_dummy_toaster;

typedef struct dummy_node dummy_node;
struct dummy_node
{
	dummy_node *next;
	int32 toasted_length;
	char *toasted_data;
};

#define VARATT_DUMMY_HDRSZ \
	offsetof(varatt_custom, va_toasterdata)

#define VARATT_DUMMY_TOASTER_GET_DATA(toast_pointer, attr) \
do { \
	varattrib_1b_e *attre = (varattrib_1b_e *) (attr); \
	memcpy(&(toast_pointer), VARATT_CUSTOM_GET_DATA(attre), VARATT_DUMMY_HDRSZ); \
	((varatt_custom)(toast_pointer)).va_toasterdata = VARATT_CUSTOM_GET_DATA(attre) + VARATT_DUMMY_HDRSZ; \
} while (0)

#define VARDATA_DUMMY(PTR)	(((varattrib_1b_e *) (PTR)) + VARATT_DUMMY_HDRSZ)

#define DUMMY_TOAST_MAX_CHUNK_SIZE	\
	(EXTERN_TUPLE_MAX_SIZE -							\
	 MAXALIGN(SizeofHeapTupleHeader) -					\
	 sizeof(Oid) -										\
	 sizeof(int32) -									\
	 sizeof(int32) -									\
	 VARATT_DUMMY_HDRSZ)


/* Size of an EXTERNAL datum that contains a custom TOAST pointer */
#define DUMMY_TOAST_POINTER_SIZE (VARHDRSZ_EXTERNAL + sizeof(varatt_dummy_toaster))

#define VARATT_IS_DUMMY(PTR) \
	(VARATT_IS_EXTERNAL(PTR) && VARTAG_EXTERNAL(PTR) == VARTAG_CUSTOM)

extern bool toastrel_valueid_exists(Relation toastrel, Oid valueid);
extern bool toastid_valueid_exists(Oid toastrelid, Oid valueid);

static dummy_node *head = 0;
#define MAX_DUMMY_CHUNK_SIZE 2048

/*
Datum
dummy_toast_save_datum(Relation rel, Datum value);
*/

/*
 * Validate the generic options given to a FOREIGN DATA WRAPPER, SERVER,
 * USER MAPPING or FOREIGN TABLE that uses file_fdw.
 *
 * Raise an ERROR if the option or its value is considered invalid.
 */
static struct varlena*
dummyDetoast(Relation toast_rel,
								Datum toast_ptr,
								int offset, int length)
{
	struct varlena *attr = (struct varlena *) DatumGetPointer(toast_ptr);
	/*Oid			tsrOid;*/
	struct varlena *result = palloc(VARATT_DUMMY_HDRSZ + (((varatt_custom *)(attr))->va_toasterdatalen));
	struct varlena *tptr = NULL;
	dummy_node *cur = head;
	struct varatt_custom customPtr;
	int l_offset = 0;
	int cpy_size = 0;
	int counter = 0;

	palloc(VARATT_DUMMY_HDRSZ + (((varatt_custom *)(attr))->va_toasterdatalen));
	memcpy(&customPtr, attr, (VARATT_DUMMY_HDRSZ + (((varatt_custom *)(attr))->va_toasterdatalen)));

	/* Create regular varlena and return */
	while(cur != 0 && length > 0)
	{
		cpy_size = MAX_DUMMY_CHUNK_SIZE;

		if( offset < (l_offset + MAX_DUMMY_CHUNK_SIZE) )
		{
			if(offset >= l_offset)
			{
				offset = 0;
			}
		}
		if( offset >= (l_offset + MAX_DUMMY_CHUNK_SIZE) )
			continue;

		if(length <= MAX_DUMMY_CHUNK_SIZE)
		{
			cpy_size = length;
		}
		tptr = (result + VARHDRSZ_EXTERNAL + counter * MAX_DUMMY_CHUNK_SIZE);
		memcpy(tptr, (attr + VARATT_DUMMY_HDRSZ + l_offset), cpy_size);
		counter++;
		length -= MAX_DUMMY_CHUNK_SIZE;
		cur = head->next;
	}

	pfree(head);
	return result;
}

static struct varlena*
dummyToast(Relation toast_rel,
								Datum value, Datum oldvalue,
								int max_inline_size)
{
	Datum		tsrDatum = value;
	struct varlena *attr = (struct varlena *) DatumGetPointer(tsrDatum);
	struct varatt_custom *dptr = palloc(VARHDRSZ_EXTERNAL + ((varatt_custom *)(attr))->va_rawsize);
	struct varlena *result = NULL;
	struct dummy_node *cur, *prev;
	int l_offset = 0;
	int l_length = 0;
	int cpy_size = 0;
	int counter = 0;
	struct varatt_custom *new_ptr;

	if(VARATT_IS_CUSTOM(attr))
	{
		memcpy(dptr, VARATT_CUSTOM_GET_DATA(attr), ((varatt_external *)(attr))->va_rawsize);
		l_length = ((varatt_external *)(attr))->va_rawsize;
		prev = head;
		while(l_length > 0)
		{
			cpy_size = MAX_DUMMY_CHUNK_SIZE;
			if(l_length < MAX_DUMMY_CHUNK_SIZE)
			{
				cpy_size = l_length;
			}

			new_ptr = palloc(VARHDRSZ_EXTERNAL + cpy_size);
			cur = palloc(sizeof(dummy_node*) + sizeof(int32) + cpy_size);
			memcpy((cur->toasted_data), (dptr->va_toasterdata + l_offset), cpy_size);
			memcpy(new_ptr->va_toasterdata, (dptr->va_toasterdata + l_offset), cpy_size);
			memcpy(new_ptr, dptr, VARHDRSZ_EXTERNAL);
			new_ptr->va_toasterdatalen = cpy_size;
			cur->toasted_length = cpy_size;
			cur->next = 0;
			l_length -= MAX_DUMMY_CHUNK_SIZE;
			l_offset += MAX_DUMMY_CHUNK_SIZE;
			if(counter == 0)
			{
				head = cur;
				prev = cur;
			}
			else
			{
				prev->next = cur;
			}
			prev = cur;
			counter++;
			pfree(new_ptr);
		}
		result = (struct varlena *) head;
		pfree(dptr);
		return result;

	}
	if(VARATT_IS_EXTERNAL(attr))
	{
		memcpy(dptr, (attr + VARHDRSZ_EXTERNAL), ((varatt_external *)(attr))->va_rawsize);
		dptr->va_version = 1;
		dptr->va_toasterdatalen = (((varatt_external *)(attr))->va_rawsize);
		memcpy(result, dptr, sizeof(*dptr));
		pfree(dptr);
		return result;
	}
	else
	{
		return NULL;
	}
}

static bool
dummyToasterValidate(Oid typeoid,  char storage, char compression,
					 Oid amoid, bool false_ok)
{
	bool result = true;

	return result;
}
/*
static struct varlena *
dummy_toaster_get_pointer(Oid toasterid, struct varatt_external *ptr,
						   Size data_size, char **pdata)
{
	Size size = (VARATT_DUMMY_HDRSZ + data_size);
	struct varlena *result = palloc(size);
	varatt_dummy_toaster result_data;
	varatt_custom va_custom;

	SET_VARTAG_EXTERNAL(result, VARTAG_CUSTOM);

	va_custom.va_toasterid = toasterid;
	va_custom.va_toasterdatalen = VARATT_DUMMY_HDRSZ + data_size;
	memcpy(VARDATA_EXTERNAL(result), &va_custom, sizeof(va_custom));

	result_data.toast_ptr = *ptr;

	memcpy(VARATT_CUSTOM_GET_DATA(result), &result_data, VARATT_DUMMY_HDRSZ);

	if (pdata)
		*pdata = VARATT_CUSTOM_GET_DATA(result) + VARATT_DUMMY_HDRSZ;

	return result;
}
*/

Datum
dummy_toaster_handler(PG_FUNCTION_ARGS)
{
	TsrRoutine *tsrroutine = makeNode(TsrRoutine);
	tsrroutine->toast = dummyToast;
	tsrroutine->detoast = dummyDetoast;
	tsrroutine->get_vtable = NULL;
	tsrroutine->toastervalidate = dummyToasterValidate;
	PG_RETURN_POINTER(tsrroutine);
}
