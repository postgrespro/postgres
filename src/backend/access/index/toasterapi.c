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
#include "access/reloptions.h"
#include "access/toasterapi.h"
#include "access/table.h"
#include "access/xact.h"
#include "catalog/catalog.h"
#include "catalog/indexing.h"
#include "miscadmin.h"
#include "utils/fmgroids.h"
#include "utils/rel.h"
#include "utils/snapmgr.h"
#include "catalog/pg_namespace.h"
#include "utils/guc.h"

#include "catalog/binary_upgrade.h"
#include "catalog/dependency.h"
#include "catalog/heap.h"
#include "catalog/index.h"
#include "catalog/namespace.h"
#include "catalog/pg_am.h"
#include "catalog/pg_class.h"
#include "catalog/pg_opclass.h"
#include "catalog/pg_type.h"
#include "catalog/toasting.h"
#include "nodes/makefuncs.h"
#include "storage/lock.h"

#include "access/multixact.h"
#include "access/relation.h"
#include "access/transam.h"
#include "access/visibilitymap.h"
#include "catalog/pg_am_d.h"
#include "commands/vacuum.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "storage/bufmgr.h"
#include "storage/freespace.h"
#include "storage/lmgr.h"
#include "storage/procarray.h"


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

typedef struct ToastrelCacheEntry
{
	Toastrel		tkey;
} ToastrelCacheEntry;

static List	*ToastrelCache = NIL;

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
GetToastRelation(Oid toasteroid, Oid relid, Oid toastentid, int16 version, int16 attnum, LOCKMODE lockmode)
{
	Relation		pg_toastrel;
	ScanKeyData key[4];
	SysScanDesc scan;
	HeapTuple	tup;
	uint32      total_entries = 0;
//	Toastrel	  	rel = NULL;
/*	MemoryContext myctx, oldctx; */
	int keys = 0;
	Toastkey		tkey;
/*
	myctx = AllocSetContextCreate(CurrentMemoryContext, "ToastrelCtx", ALLOCSET_DEFAULT_SIZES);
	oldctx = MemoryContextSwitchTo(myctx);
*/

	tkey = palloc(sizeof(ToastrelKey));
	tkey->toastentid = InvalidOid;
	tkey->attnum = 0;

	elog(NOTICE, "GetToastRelation enter rel %u", relid);
	pg_toastrel = table_open(ToastrelRelationId, lockmode);
/*
	if( toasteroid != InvalidOid )
	{
		ScanKeyInit(&key[keys],
				Anum_pg_toastrel_toasteroid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(toasteroid));
		keys++;
	}
*/
	if( relid != InvalidOid )
	{
		ScanKeyInit(&key[keys],
				Anum_pg_toastrel_relid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(relid));
		keys++;
	}
/*
	if( version >= 0 )
	{
		ScanKeyInit(&key[keys],
				Anum_pg_toastrel_version,
				BTEqualStrategyNumber, F_INT2EQ,
				Int16GetDatum(version));
		keys++;
	}
*/
	if( attnum >= 0 )
	{
		ScanKeyInit(&key[keys],
				Anum_pg_toastrel_attnum,
				BTEqualStrategyNumber, F_INT2EQ,
				Int16GetDatum(attnum));
		keys++;
	}
	scan = systable_beginscan(pg_toastrel, ToastrelRelIndexId, false,
							  NULL, keys, key);
	keys = 0;
	elog(NOTICE, "Cycle start");
	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		total_entries++;
		elog(NOTICE, "Found TOAST toasterid %u relid %u toastent %u attnum %u",
			 ((Form_pg_toastrel) GETSTRUCT(tup))->toasteroid,
			 ((Form_pg_toastrel) GETSTRUCT(tup))->relid,
			 ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid,
			 ((Form_pg_toastrel) GETSTRUCT(tup))->attnum);

		if( ((Form_pg_toastrel) GETSTRUCT(tup))->relid== relid 
			&& ((Form_pg_toastrel) GETSTRUCT(tup))->attnum == attnum )
		{
			if( ((Form_pg_toastrel) GETSTRUCT(tup))->version >= keys )
			{
				keys = ((Form_pg_toastrel) GETSTRUCT(tup))->version;
//				tkey = palloc(sizeof(ToastrelKey));
				tkey->toastentid = ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid;
				tkey->attnum = ((Form_pg_toastrel) GETSTRUCT(tup))->version;
			}
			break;
		}

	}

	systable_endscan(scan);
	table_close(pg_toastrel, lockmode);
/*
	MemoryContextSwitchTo(oldctx);
*/
	return PointerGetDatum(tkey);
}

/* ----------
 * GetToastRelation -
 *
 *	Retrieve single TOAST relation from pg_toastrel according to
 *	given key. If not found create a new one
 * ----------
 */
Datum
GetLastToastrel(Oid relid, int16 attnum, LOCKMODE lockmode)
{
	Relation		pg_toastrel;
	ScanKeyData key[4];
	SysScanDesc scan;
	HeapTuple	tup;
	uint32      total_entries = 0;
//	Toastrel	  	rel = NULL;
/*	MemoryContext myctx, oldctx; */
	int keys = 0;
	int def_keys = 0;
	Toastkey		tkey;
	Oid			trel = InvalidOid;
	int16			version = 0;
/*
	myctx = AllocSetContextCreate(CurrentMemoryContext, "ToastrelCtx", ALLOCSET_DEFAULT_SIZES);
	oldctx = MemoryContextSwitchTo(myctx);
*/

	tkey = palloc(sizeof(ToastrelKey));
	tkey->toastentid = InvalidOid;
	tkey->toasterid = InvalidOid;
	tkey->attnum = 0;

	elog(NOTICE, "GetToastRelation enter rel %u", relid);
	pg_toastrel = table_open(ToastrelRelationId, lockmode);

	if( relid != InvalidOid )
	{
		ScanKeyInit(&key[keys],
				Anum_pg_toastrel_relid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(relid));
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

	scan = systable_beginscan(pg_toastrel, ToastrelRelIndexId, false,
							  NULL, keys, key);
	keys = 0;
	elog(NOTICE, "Cycle start");
	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		total_entries++;
		elog(NOTICE, "Found TOAST toasterid %u relid %u toastent %u attnum %u",
			 ((Form_pg_toastrel) GETSTRUCT(tup))->toasteroid,
			 ((Form_pg_toastrel) GETSTRUCT(tup))->relid,
			 ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid,
			 ((Form_pg_toastrel) GETSTRUCT(tup))->attnum);

		if(((Form_pg_toastrel) GETSTRUCT(tup))->relid == relid)
		{
			if(((Form_pg_toastrel) GETSTRUCT(tup))->toasteroid == DEFAULT_TOASTER_OID
				&& ((Form_pg_toastrel) GETSTRUCT(tup))->version >= def_keys )
			{
				trel = ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid;
				version = ((Form_pg_toastrel) GETSTRUCT(tup))->version;
				def_keys = ((Form_pg_toastrel) GETSTRUCT(tup))->version;
			}
			
			if(((Form_pg_toastrel) GETSTRUCT(tup))->attnum == attnum
				&& ((Form_pg_toastrel) GETSTRUCT(tup))->version >= keys )
			{
				keys = ((Form_pg_toastrel) GETSTRUCT(tup))->version;
				tkey->toasterid = ((Form_pg_toastrel) GETSTRUCT(tup))->toasteroid;
				tkey->toastentid = ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid;
				tkey->attnum = ((Form_pg_toastrel) GETSTRUCT(tup))->version;
			}
			break;
		}
	}

	if(tkey->toasterid == InvalidOid)
	{
		tkey->toasterid = DEFAULT_TOASTER_OID;
		tkey->toastentid = trel;
		tkey->attnum = version;
	}

	systable_endscan(scan);
	table_close(pg_toastrel, lockmode);
/*
	MemoryContextSwitchTo(oldctx);
*/
	return PointerGetDatum(tkey);
}

/* ----------
 * GetToastRelation -
 *
 *	Retrieve single TOAST relation from pg_toastrel according to
 *	given key. If not found create a new one
 * ----------
 */
Datum
GetFullToastrel(Oid relid, int16 attnum, LOCKMODE lockmode)
{
	Relation		pg_toastrel;
	ScanKeyData key[4];
	SysScanDesc scan;
	HeapTuple	tup;
	uint32      total_entries = 0;
//	Toastrel	  	rel = NULL;
/*	MemoryContext myctx, oldctx; */
	int keys = 0;
	int def_keys = 0;
	Toastrel		tkey, tmpkey;
/*
	myctx = AllocSetContextCreate(CurrentMemoryContext, "ToastrelCtx", ALLOCSET_DEFAULT_SIZES);
	oldctx = MemoryContextSwitchTo(myctx);
*/

	tkey = palloc(sizeof(ToastrelKey));
	tkey->toastentid = InvalidOid;
	tkey->toasteroid = InvalidOid;
	tkey->attnum = 0;

	tmpkey = palloc(sizeof(ToastrelKey));
	tmpkey->toastentid = InvalidOid;
	tmpkey->toasteroid = InvalidOid;
	tmpkey->attnum = 0;

	elog(NOTICE, "GetToastRelation enter rel %u", relid);
	pg_toastrel = table_open(ToastrelRelationId, lockmode);

	if( relid != InvalidOid )
	{
		ScanKeyInit(&key[keys],
				Anum_pg_toastrel_relid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(relid));
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

	scan = systable_beginscan(pg_toastrel, ToastrelRelIndexId, false,
							  NULL, keys, key);
	keys = 0;
	elog(NOTICE, "Cycle start");
	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		total_entries++;
		elog(NOTICE, "Found TOAST toasterid %u relid %u toastent %u attnum %u",
			 ((Form_pg_toastrel) GETSTRUCT(tup))->toasteroid,
			 ((Form_pg_toastrel) GETSTRUCT(tup))->relid,
			 ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid,
			 ((Form_pg_toastrel) GETSTRUCT(tup))->attnum);

		if(((Form_pg_toastrel) GETSTRUCT(tup))->relid == relid)
		{
			if(((Form_pg_toastrel) GETSTRUCT(tup))->toasteroid == DEFAULT_TOASTER_OID
				&& ((Form_pg_toastrel) GETSTRUCT(tup))->version >= def_keys )
			{
				tmpkey->toastentid = ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid;
				tmpkey->version = ((Form_pg_toastrel) GETSTRUCT(tup))->version;
				tmpkey->attnum = ((Form_pg_toastrel) GETSTRUCT(tup))->attnum;
				tmpkey->relid = ((Form_pg_toastrel) GETSTRUCT(tup))->relid;
				tmpkey->toasteroid = ((Form_pg_toastrel) GETSTRUCT(tup))->toasteroid;
				tmpkey->toastoptions = ((Form_pg_toastrel) GETSTRUCT(tup))->toastoptions;
			}
			
			if(((Form_pg_toastrel) GETSTRUCT(tup))->attnum == attnum
				&& ((Form_pg_toastrel) GETSTRUCT(tup))->version >= keys )
			{
				keys = ((Form_pg_toastrel) GETSTRUCT(tup))->version;

				tkey->toastentid = ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid;
				tkey->version = ((Form_pg_toastrel) GETSTRUCT(tup))->version;
				tkey->attnum = ((Form_pg_toastrel) GETSTRUCT(tup))->attnum;
				tkey->relid = ((Form_pg_toastrel) GETSTRUCT(tup))->relid;
				tkey->toasteroid = ((Form_pg_toastrel) GETSTRUCT(tup))->toasteroid;
				tkey->toastoptions = ((Form_pg_toastrel) GETSTRUCT(tup))->toastoptions;

			}
			break;
		}
	}

	if(tkey->toasteroid == InvalidOid)
	{
		pfree(tkey);
		tkey = tmpkey;
	}
	else
		pfree(tmpkey);

	systable_endscan(scan);
	table_close(pg_toastrel, lockmode);
/*
	MemoryContextSwitchTo(oldctx);
*/
	return PointerGetDatum(tkey);
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
	Toastkey		tkey;
	Datum		values[Natts_pg_toastrel];
	bool		nulls[Natts_pg_toastrel];

	if (toasteroid == InvalidOid || relid == InvalidOid || toastentid == InvalidOid)
	{
		return false;
	}

	tkey = (Toastkey)DatumGetPointer(GetLastToastrel(relid, attnum, AccessShareLock));

	memset(nulls, false, sizeof(nulls));

	pg_toastrel = table_open(ToastrelRelationId, lockmode);
	{
		Oid			oid = GetNewOidWithIndex(pg_toastrel, ToastrelOidIndexId,
											 Anum_pg_toastrel_oid);

		values[Anum_pg_toastrel_oid - 1] = ObjectIdGetDatum(oid);
		values[Anum_pg_toastrel_toasteroid - 1] = ObjectIdGetDatum(toasteroid);
		values[Anum_pg_toastrel_relid - 1] = ObjectIdGetDatum(relid);
		values[Anum_pg_toastrel_toastentid - 1] = ObjectIdGetDatum(toastentid);
		values[Anum_pg_toastrel_attnum - 1] = Int16GetDatum(attnum);
		values[Anum_pg_toastrel_version - 1] = Int16GetDatum(tkey->attnum + 1);
		values[Anum_pg_toastrel_relname - 1] = NameGetDatum(&relname);
		values[Anum_pg_toastrel_toastentname - 1] = NameGetDatum(&toastentname);
		values[Anum_pg_toastrel_toastoptions - 1] = CharGetDatum(toastoptions);

		tup = heap_form_tuple(RelationGetDescr(pg_toastrel), values, nulls);

		elog(NOTICE, "Insert TOAST toasterid %u relid %u toastent %u attnum %u version %u",
			 ((Form_pg_toastrel) GETSTRUCT(tup))->toasteroid,
			 ((Form_pg_toastrel) GETSTRUCT(tup))->relid,
			 ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid,
			 ((Form_pg_toastrel) GETSTRUCT(tup))->attnum,
			 ((Form_pg_toastrel) GETSTRUCT(tup))->version);

		CatalogTupleInsert(pg_toastrel, tup);
		heap_freetuple(tup);
	}
	CommandCounterIncrement();
	table_close(pg_toastrel, lockmode);
	return true;
}

/* ----------
 * InsertToastRelation -
 *
 *	Insert single TOAST relation into pg_toastrel
 * ----------
 */
bool
UpdateToastRelation(Oid treloid, Oid toasteroid, Oid relid, Oid toastentid, int16 attnum,
	int version, char flag, LOCKMODE lockmode)
{
	Relation		pg_toastrel;
	ScanKeyData key[4];
	SysScanDesc scan;
	HeapTuple	tup;
	HeapTuple	newtup;
	Datum		values[Natts_pg_toastrel];
	bool		nulls[Natts_pg_toastrel];
	bool		replaces[Natts_pg_toastrel];
	int keys = 0;

	if (toasteroid == InvalidOid || relid == InvalidOid)
	{
		return false;
	}

	memset(nulls, false, sizeof(nulls));

	pg_toastrel = table_open(ToastrelRelationId, lockmode);

	if(treloid != InvalidOid)
	{
		ScanKeyInit(&key[0],
				Anum_pg_toastrel_toasteroid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(toasteroid));
		keys++;
	}
	else
	{
		ScanKeyInit(&key[0],
				Anum_pg_toastrel_toasteroid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(toasteroid));
		keys++;
		ScanKeyInit(&key[1],
				Anum_pg_toastrel_relid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(relid));
		keys++;
		ScanKeyInit(&key[2],
				Anum_pg_toastrel_attnum,
				BTEqualStrategyNumber, F_INT2EQ,
				Int16GetDatum(attnum));
		keys++;
		ScanKeyInit(&key[3],
				Anum_pg_toastrel_version,
				BTEqualStrategyNumber, F_INT2EQ,
				Int16GetDatum(version));
		keys++;
	}

	scan = systable_beginscan(pg_toastrel, ToastrelKeyIndexId, true,
							  NULL, keys, key);

	while (HeapTupleIsValid((tup = systable_getnext(scan))))
	{
/*		Form_pg_toastrel trelform = (Form_pg_toastrel) GETSTRUCT(tup); */

		values[Anum_pg_toastrel_flag - 1] = CharGetDatum(flag);
		replaces[Anum_pg_toastrel_flag - 1] = true;

		newtup = heap_modify_tuple(tup, RelationGetDescr(pg_toastrel),
										 values, nulls, replaces);
		CatalogTupleUpdate(pg_toastrel, &newtup->t_self, newtup);

		heap_freetuple(tup);
	}

	systable_endscan(scan);
	CommandCounterIncrement();
	table_close(pg_toastrel, lockmode);
	return true;
}

/*
 * SearchToastrelCache - get cached pg_toastrel record
 */
Datum
InsertToastrelCache(Oid treloid, Oid toasteroid, Oid relid, Oid toastentid, int16 attnum,
	int16 version, NameData relname, NameData toastentname, char toastoptions)
{
	ToastrelCacheEntry  *entry;
	MemoryContext		ctx;
	ctx = MemoryContextSwitchTo(CacheMemoryContext);

	/* make a new one */

	entry = palloc(sizeof(*entry));
	entry->tkey = palloc(sizeof(ToastrelData));
	
	entry->tkey->toasteroid = toasteroid;
	entry->tkey->relid = relid;
	entry->tkey->attnum = attnum;
	entry->tkey->version = version;
	entry->tkey->oid = treloid;
	entry->tkey->toastentid = toastentid;
	entry->tkey->toastoptions = toastoptions;

	ToastrelCache = lcons(entry, ToastrelCache);

	MemoryContextSwitchTo(ctx);

	return PointerGetDatum(entry->tkey);
}

/*
 * SearchToastrelCache - get cached pg_toastrel record
 */
Datum
DeleteToastrelCache(Oid toasterid, Oid	relid, int16 attnum)
{
	ListCell		   *lc;
	ToastrelCacheEntry  *entry;
	MemoryContext		ctx;
	Datum result = (Datum) 0;

	if (list_length(ToastrelCache) > 0)
	{
		/* fast path */
		entry = (ToastrelCacheEntry*)linitial(ToastrelCache);
		if (entry->tkey->relid == relid
			&& entry->tkey->attnum == attnum
			&& entry->tkey->toasteroid == toasterid)
			return PointerGetDatum(entry->tkey);
	}

	/* didn't find in first position */
	ctx = MemoryContextSwitchTo(CacheMemoryContext);

	for_each_from(lc, ToastrelCache, 0)
	{
		entry = (ToastrelCacheEntry*)lfirst(lc);

		if (entry->tkey->relid == relid
			&& entry->tkey->attnum == attnum
			&& entry->tkey->toasteroid == toasterid)
		{
			result = PointerGetDatum(entry->tkey);
			foreach_delete_current(ToasterCache, lc);
			goto out;
		}
	}

out:
	MemoryContextSwitchTo(ctx);

	return result;
}

/*
 * SearchToastrelCache - get cached pg_toastrel record
 */
Datum
SearchToastrelCache(Oid	relid, int16 attnum, bool search_ind)
{
	ListCell		   *lc;
	ToastrelCacheEntry  *entry;
	MemoryContext		ctx;
	Datum result = (Datum) 0;
	Toastrel tkey;

	if (list_length(ToastrelCache) > 0)
	{
		/* fast path */
		entry = (ToastrelCacheEntry*)linitial(ToastrelCache);
		if (entry->tkey->relid == relid
			&& entry->tkey->attnum == attnum)
			return PointerGetDatum(entry->tkey);
	}

	/* didn't find in first position */
	ctx = MemoryContextSwitchTo(CacheMemoryContext);

lookup:
	for_each_from(lc, ToastrelCache, 0)
	{
		entry = (ToastrelCacheEntry*)lfirst(lc);

		if (entry->tkey->relid == relid
			&& entry->tkey->attnum == attnum)
		{
			result = PointerGetDatum(entry->tkey);
			goto out;
		}
	}

	tkey = (Toastrel) DatumGetPointer(GetFullToastrel(relid, attnum, AccessShareLock));
	InsertToastrelCache(InvalidOid, tkey->toasteroid, relid, tkey->toastentid, attnum,
	tkey->version, tkey->relname, tkey->toastentname, tkey->toastoptions);
	goto lookup;

out:
	MemoryContextSwitchTo(ctx);

	return result;
}

/*
 * SearchToastrelCache - get cached pg_toastrel record
 */
Datum
InsertOrReplaceToastrelCache(Oid treloid, Oid toasteroid, Oid relid, Oid toastentid, int16 attnum,
	NameData relname, NameData toastentname, char toastoptions)
{
	ListCell		   *lc;
	ToastrelCacheEntry  *entry;
	MemoryContext		ctx;
	Datum result = (Datum) 0;
	Toastrel tkey;
	Toastrel lastkey = NULL;

	ctx = MemoryContextSwitchTo(CacheMemoryContext);

	for_each_from(lc, ToastrelCache, 0)
	{
		entry = (ToastrelCacheEntry*)lfirst(lc);

		if (entry->tkey->relid == relid
			&& entry->tkey->attnum == attnum)
		{
			tkey = entry->tkey;
			if(lastkey->version <= entry->tkey->version)
				lastkey = entry->tkey;
		}
	}

	entry = palloc(sizeof(*entry));
	entry->tkey = palloc(sizeof(ToastrelData));
	
	entry->tkey->toasteroid = toasteroid;
	entry->tkey->relid = relid;
	entry->tkey->attnum = attnum;
	entry->tkey->version = 0;
	entry->tkey->oid = treloid;
	entry->tkey->toastentid = toastentid;
	entry->tkey->toastoptions = toastoptions;

	if(lastkey != NULL)
		entry->tkey->version = lastkey->version + 1;

	ToastrelCache = lcons(entry, ToastrelCache);

	tkey = (Toastrel) DatumGetPointer(GetFullToastrel(relid, attnum, AccessShareLock));
	InsertToastRelation(tkey->toasteroid, relid, tkey->toastentid, attnum,
	tkey->version, tkey->relname, tkey->toastentname, tkey->toastoptions, AccessExclusiveLock);

	MemoryContextSwitchTo(ctx);

	return result;
}

Datum
relopts_get_toaster_opts(Datum reloptions, Oid *relid, Oid *toasterid)
{
	List	   *options_list = untransformRelOptions(reloptions);
	ListCell   *cell;

	foreach(cell, options_list)
	{
		DefElem    *def = (DefElem *) lfirst(cell);

		if (strcmp(def->defname, "relationoid") == 0
			|| strcmp(def->defname, "toasteroid") == 0)
		{
			char	   *value;
			int			int_val;
			bool		is_parsed;

			value = defGetString(def);
			is_parsed = parse_int(value, &int_val, 0, NULL);

			if (!is_parsed)
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						 errmsg("invalid value for integer option \"%s\": %s",
								def->defname, value)));

			if (int_val <= 0)
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						 errmsg("\"%s\" must be an integer value greater than zero",
								def->defname)));
			if(strcmp(def->defname, "relationoid") == 0)
				*relid = int_val;
			if(strcmp(def->defname, "toasteroid") == 0)
				*toasterid = int_val;
		}
	}
	return ObjectIdGetDatum(*relid);
}

Datum
relopts_set_toaster_opts(Datum reloptions, Oid relid, Oid toasterid)
{
	Datum toast_options;
	List    *defList = NIL;
	static char *validnsps[] = HEAP_RELOPT_NAMESPACES;
	{
		defList = lappend(defList, makeDefElem("toasteroid", (Node *) makeInteger(toasterid), -1));
		defList = lappend(defList, makeDefElem("toastrelid", (Node *) makeInteger(relid), -1));
	}

	toast_options = transformRelOptions(reloptions,
									 defList, NULL, validnsps, false,
									 false);

	(void) heap_reloptions(RELKIND_TOASTVALUE, toast_options, false);
	return toast_options;
}