/*-------------------------------------------------------------------------
 *
 * toasterapi.c
 *	  Support routines for API for Postgres PG_TOASTER methods.
 *
 * Copyright (c) 2015-2021, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *	  src/backend/access/index/toasterapi.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/toasterapi.h"
#include "access/htup_details.h"
#include "catalog/pg_toaster.h"
#include "catalog/pg_toastrel.h"
#include "catalog/pg_toastrel_d.h"
#include "commands/defrem.h"
#include "lib/pairingheap.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "access/heaptoast.h"
#include "access/table.h"
#include "access/xact.h"
#include "catalog/catalog.h"
#include "catalog/indexing.h"
#include "miscadmin.h"
#include "utils/fmgroids.h"
#include "utils/rel.h"
#include "utils/snapmgr.h"



/*
 * Toasters is very often called so syscache lookup and TsrRoutine allocation are
 * expensive and we need to cache them.
 *
 * We believe what there are only a few toasters and there is high chance that
 * only one or only two of them are heavy used, so most used toasters should be
 * found as easy as possible. So, let us use a simple list, in future it could
 * be changed to other structure. For now it will be stored in TopCacheContext
 * and never destroed in backend life cycle - toasters are never deleted.
 */

typedef struct ToasterCacheEntry
{
	Oid			toasterOid;
	TsrRoutine *routine;
} ToasterCacheEntry;

static List	*ToasterCache = NIL;

/*
 * SearchTsrCache - get cached toaster routine, emits an error if toaster
 * doesn't exist
 */
TsrRoutine*
SearchTsrCache(Oid	toasterOid)
{
	ListCell		   *lc;
	ToasterCacheEntry  *entry;
	MemoryContext		ctx;

	if (list_length(ToasterCache) > 0)
	{
		/* fast path */
		entry = (ToasterCacheEntry*)linitial(ToasterCache);
		if (entry->toasterOid == toasterOid)
			return entry->routine;
	}

	/* didn't find in first position */
	ctx = MemoryContextSwitchTo(CacheMemoryContext);

	for_each_from(lc, ToasterCache, 0)
	{
		entry = (ToasterCacheEntry*)lfirst(lc);

		if (entry->toasterOid == toasterOid)
		{
			/* XXX NMalakhov: */
			/* Questionable approach - should we re-arrange TOASTer cache 		*/
			/* on cache hit for non-first entry or not. We suggest that there 	*/
			/* won't be a lot of Toasters, and most used still will be the 		*/
			/* default (generic) one. Re-arranging is commented until final		*/
			/* decision is to be made */
			/* remove entry from list, it will be added in a head of list below */
			/*
			foreach_delete_current(ToasterCache, lc);
			*/
			goto out;
		}
	}

	/* did not find entry, make a new one */
	entry = palloc(sizeof(*entry));

	entry->toasterOid = toasterOid;
	entry->routine = GetTsrRoutineByOid(toasterOid, false);

/* XXX NMalakhov: label moved further wi re-arranging commented. Insertion into */
/* ToasterCache changed from prepend to append, fot the first used Toaster 		*/
/* (almost always the default one) to be the first one. Also appending does not */
/* move all the entries around */
/* out: */
	/*
	ToasterCache = lcons(entry, ToasterCache);
	*/
	ToasterCache = lappend(ToasterCache, entry);

out:
	MemoryContextSwitchTo(ctx);

	return entry->routine;
}

/*
 * GetRoutine - call the specified toaster handler routine to get
 * its TsrRoutine struct, which will be palloc'd in the caller's context.
 *
 */
TsrRoutine *
GetTsrRoutine(Oid tsrhandler)
{
	Datum		datum;
	TsrRoutine *routine;

	datum = OidFunctionCall0(tsrhandler);
	routine = (TsrRoutine *) DatumGetPointer(datum);

	if (routine == NULL || !IsA(routine, TsrRoutine))
		elog(ERROR, "toaster handler function %u did not return an TsrRoutine struct",
			 tsrhandler);

	return routine;
}

/*
 * GetTsrRoutineByOid - look up the handler of the toaster
 * with the given OID, and get its TsrRoutine struct.
 *
 * If the given OID isn't a valid toaster, returns NULL if
 * noerror is true, else throws error.
 */
TsrRoutine *
GetTsrRoutineByOid(Oid tsroid, bool noerror)
{
	HeapTuple	tuple;
	Form_pg_toaster	tsrform;
	regproc		tsrhandler;

	/* Get handler function OID for the access method */
	tuple = SearchSysCache1(TOASTEROID, ObjectIdGetDatum(tsroid));
	if (!HeapTupleIsValid(tuple))
	{
		if (noerror)
			return NULL;
		elog(ERROR, "cache lookup failed for toaster %u",
			 tsroid);
	}
	tsrform = (Form_pg_toaster) GETSTRUCT(tuple);

	tsrhandler = tsrform->tsrhandler;

	/* Complain if handler OID is invalid */
	if (!RegProcedureIsValid(tsrhandler))
	{
		if (noerror)
		{
			ReleaseSysCache(tuple);
			return NULL;
		}
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("toaster \"%s\" does not have a handler",
						NameStr(tsrform->tsrname))));
	}

	ReleaseSysCache(tuple);

	/* And finally, call the handler function to get the API struct. */
	return GetTsrRoutine(tsrhandler);
}

/*
 * could toaster operates with given type and access method?
 * If it can't then validate method should emit an error if false_ok = false
 */
bool
validateToaster(Oid toasteroid, Oid typeoid,
				char storage, char compression, Oid amoid, bool false_ok)
{
	TsrRoutine *tsrroutine;
	bool	result = true;

	if (!TypeIsToastable(typeoid))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("data type %s can not be toasted",
						format_type_be(typeoid))));

	tsrroutine = GetTsrRoutineByOid(toasteroid, false_ok);

	/* if false_ok == false then GetTsrRoutineByOid emits an error */
	if (tsrroutine == NULL)
		return false;

#if 0 /* XXX teodor: commented out while there is no actual toaster */
	/* should not happen */
	if (tsrroutine->toastervalidate == NULL)
		elog(ERROR, "function toastervalidate is not defined for toaster %s",
			 get_toaster_name(toasteroid));

	result = tsrroutine->toastervalidate(typeoid, storage, compression,
										 amoid, false_ok);
#endif

	pfree(tsrroutine);

	return result;
}

/* ----------
 * GetToastRelation -
 *
 *	Retrieve single TOAST relation from pg_toastrel according to
 *	given key. If not found create a new one
 * ----------
 */
Datum
GetToastRelation(Oid toasteroid, Oid relid, Oid toastentid, int16 attnum, LOCKMODE lockmode)
{
	Relation		pg_toastrel;
	ScanKeyData key[4];
	SysScanDesc scan;
	HeapTuple	tup;
	uint32      total_entries = 0;
//	Toastrel	  	rel = NULL;
	MemoryContext myctx, oldctx;
	int keys = 0;
	Oid			trel_oid = InvalidOid;
/*
	myctx = AllocSetContextCreate(CurrentMemoryContext, "ToastrelCtx", ALLOCSET_DEFAULT_SIZES);
	oldctx = MemoryContextSwitchTo(myctx);
*/
	pg_toastrel = table_open(ToastrelRelationId, lockmode);

	if( toasteroid != InvalidOid )
	{
		ScanKeyInit(&key[keys],
				Anum_pg_toastrel_toasteroid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(toasteroid));
		keys++;
	}

	if( relid != InvalidOid )
	{
		ScanKeyInit(&key[keys],
				Anum_pg_toastrel_relid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(relid));
		keys++;
	}

	if( toastentid != InvalidOid )
	{
		ScanKeyInit(&key[keys],
				Anum_pg_toastrel_toastentid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(toastentid));
		keys++;
	}

	if( attnum >= 0 )
	{
		ScanKeyInit(&key[keys],
				Anum_pg_toastrel_attnum,
				BTEqualStrategyNumber, F_INT2EQ,
				Int16GetDatum(attnum));
		keys++;
	}

	scan = systable_beginscan(pg_toastrel, ToastrelKeyIndexId, false,
							  NULL, keys, key);

	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
/*		ToastrelData d;

		d.oid = ((Form_pg_toastrel) GETSTRUCT(tup))->oid;
		d.toasteroid = ((Form_pg_toastrel) GETSTRUCT(tup))->toasteroid;
		d.relid = ((Form_pg_toastrel) GETSTRUCT(tup))->relid;
		d.toastentid = ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid;
		d.attnum = ((Form_pg_toastrel) GETSTRUCT(tup))->attnum;
		d.version = ((Form_pg_toastrel) GETSTRUCT(tup))->version;
		d.relname = ((Form_pg_toastrel) GETSTRUCT(tup))->relname;
		d.toastentname = ((Form_pg_toastrel) GETSTRUCT(tup))->toastentname;
		d.description = ((Form_pg_toastrel) GETSTRUCT(tup))->description;
		d.toastoptions = ((Form_pg_toastrel) GETSTRUCT(tup))->toastoptions;
*/
		total_entries++;

		if( toasteroid != InvalidOid && relid != InvalidOid && attnum >= 0
			&& ((Form_pg_toastrel) GETSTRUCT(tup))->toasteroid == toasteroid 
			&& ((Form_pg_toastrel) GETSTRUCT(tup))->relid== relid 
			&& ((Form_pg_toastrel) GETSTRUCT(tup))->attnum == attnum )
		{
			trel_oid = ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid;
/*			rel = palloc(sizeof(ToastrelData));
			memcpy( rel, &d, sizeof(ToastrelData) ); */
			break;
		}

	}

	systable_endscan(scan);
	table_close(pg_toastrel, lockmode);
/*
	MemoryContextSwitchTo(oldctx);
*/
	return ObjectIdGetDatum(trel_oid); // PointerGetDatum(rel);
}

/* ----------
 * InsertToastRelation -
 *
 *	Insert single TOAST relation into pg_toastrel
 * ----------
 */
bool
InsertToastRelation(Oid toasteroid, Oid relid, Oid toastentid, int16 attnum,
	int version, NameData relname, NameData toastentname, char toastoptions, LOCKMODE lockmode)
{
	Relation		pg_toastrel;
	HeapTuple	tup;
	Datum		values[Natts_pg_toastrel];
	bool		nulls[Natts_pg_toastrel];

	if (toasteroid == InvalidOid || relid == InvalidOid || toastentid == InvalidOid)
	{
		/* The list is empty; do nothing. */
		return false;
	}

	memset(nulls, false, sizeof(nulls));

	/*
	 * We don't check the list of values for duplicates here. If there are
	 * any, the user will get an unique-index violation.
	 */

	pg_toastrel = table_open(ToastrelRelationId, lockmode);
	{
		Oid			oid = GetNewOidWithIndex(pg_toastrel, ToastrelOidIndexId,
											 Anum_pg_toastrel_oid);

		/*
		 * Entries are stored in a name field, for easier syscache lookup, so
		 * check the length to make sure it's within range.
		 */
/*
		if (strlen(entry) > (NAMEDATALEN - 1))
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_NAME),
					 errmsg("invalid dict entry \"%s\"", entry),
					 errdetail("Entries must be %d bytes or less.",
							   NAMEDATALEN - 1)));
*/
		/* namestrcpy(&dictentry, entry); */

		values[Anum_pg_toastrel_oid - 1] = ObjectIdGetDatum(oid);
		values[Anum_pg_toastrel_toasteroid - 1] = ObjectIdGetDatum(toasteroid);
		values[Anum_pg_toastrel_relid - 1] = ObjectIdGetDatum(relid);
		values[Anum_pg_toastrel_toastentid - 1] = ObjectIdGetDatum(toastentid);
		values[Anum_pg_toastrel_attnum - 1] = Int16GetDatum(attnum);
		values[Anum_pg_toastrel_relname - 1] = NameGetDatum(&relname);
		values[Anum_pg_toastrel_toastentname - 1] = NameGetDatum(&toastentname);
		values[Anum_pg_toastrel_toastoptions - 1] = CharGetDatum(toastoptions);

		tup = heap_form_tuple(RelationGetDescr(pg_toastrel), values, nulls);

		CatalogTupleInsert(pg_toastrel, tup);
		heap_freetuple(tup);
	}

	/* clean up */
	table_close(pg_toastrel, lockmode);
	return true;
}

/* ----------
 * GetToastRelationList -
 *
 *	Retrieve all TOAST relations from pg_toastrel according to
 *	given key
 * ----------
 */
Datum
GetToastRelationList(Oid toasteroid, Oid relid, Oid toastentid, int16 attnum, LOCKMODE lockmode)
{
	Relation		pg_toastrel;
	ScanKeyData key[4];
	SysScanDesc scan;
	HeapTuple	tup;
	uint32      total_entries = 0;
	MemoryContext myctx, oldctx;
	int keys = 0;
	List *toastrel_list = NIL;

	myctx = AllocSetContextCreate(CurrentMemoryContext, "ToastrelCtx", ALLOCSET_DEFAULT_SIZES);
	oldctx = MemoryContextSwitchTo(myctx);

	pg_toastrel = table_open(ToastrelRelationId, lockmode);

	if( toasteroid != InvalidOid )
	{
		ScanKeyInit(&key[0],
				Anum_pg_toastrel_toasteroid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(toasteroid));
		keys++;
	}

	if( relid != InvalidOid )
	{
		ScanKeyInit(&key[1],
				Anum_pg_toastrel_relid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(relid));
		keys++;
	}

	if( toastentid != InvalidOid )
	{
		ScanKeyInit(&key[2],
				Anum_pg_toastrel_toastentid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(toastentid));
		keys++;
	}

	if( attnum >= 0 )
	{
		ScanKeyInit(&key[0],
				Anum_pg_toastrel_attnum,
				BTEqualStrategyNumber, F_INT2EQ,
				Int16GetDatum(attnum));
		keys++;
	}

	scan = systable_beginscan(pg_toastrel, ToastrelKeyIndexId, true,
							  NULL, keys, key);

	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		ToastrelData d;

		d.oid = ((Form_pg_toastrel) GETSTRUCT(tup))->oid;
		d.toasteroid = ((Form_pg_toastrel) GETSTRUCT(tup))->toasteroid;
		d.relid = ((Form_pg_toastrel) GETSTRUCT(tup))->relid;
		d.toastentid = ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid;
		d.attnum = ((Form_pg_toastrel) GETSTRUCT(tup))->attnum;
		d.version = ((Form_pg_toastrel) GETSTRUCT(tup))->version;
		d.relname = ((Form_pg_toastrel) GETSTRUCT(tup))->relname;
		d.toastentname = ((Form_pg_toastrel) GETSTRUCT(tup))->toastentname;
		d.description = ((Form_pg_toastrel) GETSTRUCT(tup))->description;
		d.toastoptions = ((Form_pg_toastrel) GETSTRUCT(tup))->toastoptions;

		toastrel_list = lappend(toastrel_list, &d);
		total_entries++;
	}

	systable_endscan(scan);
	table_close(pg_toastrel, lockmode);

	MemoryContextSwitchTo(oldctx);

	return PointerGetDatum(toastrel_list);
}