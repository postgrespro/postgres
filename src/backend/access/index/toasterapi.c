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
#include "catalog/pg_toaster_rel.h"
#include "catalog/pg_toaster_rel_d.h"
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
GetToastRelation(Oid toasteroid, Oid relid, Oid toastentid, int16 attnum, int32 tuplesize, LOCKMODE lockmode)
{
	Relation		pg_toastrel;
	ScanKeyData key[4];
	SysScanDesc scan;
	HeapTuple	tup;
	uint32      total_entries = 0;
/*	MemoryContext myctx, oldctx; */
	int keys = 0;
/* XXX	Oid			trel_oid = InvalidOid; */
	Toastkey		tkey = NULL;
/*
	myctx = AllocSetContextCreate(CurrentMemoryContext, "ToastrelCtx", ALLOCSET_DEFAULT_SIZES);
	oldctx = MemoryContextSwitchTo(myctx);
*/
	tkey = palloc(sizeof(ToastrelKey));
	tkey->toastentid = InvalidOid;
	tkey->attnum = 0;

	elog(NOTICE, "GetToastRelation enter rel %u", relid);
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

	if(!IsBootstrapProcessingMode())
	{
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
	}
	scan = systable_beginscan(pg_toastrel, ToastrelKeyIndexId, false,
							  NULL, keys, key);
	keys = 0;
	elog(NOTICE, "Cycle start");
	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		total_entries++;
		tkey->attnum = total_entries;
		elog(NOTICE, "Found TOAST toasterid %u relid %u toastent %u attnum %u",
			 ((Form_pg_toastrel) GETSTRUCT(tup))->toasteroid,
			 ((Form_pg_toastrel) GETSTRUCT(tup))->relid,
			 ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid,
			 ((Form_pg_toastrel) GETSTRUCT(tup))->attnum);

		if( ((Form_pg_toastrel) GETSTRUCT(tup))->toasteroid == toasteroid 
			&& ((Form_pg_toastrel) GETSTRUCT(tup))->relid== relid )
		{

			if( !IsBootstrapProcessingMode() && tuplesize > 0 )
			{
				int fs = 0;
				Relation testrel = table_open(((Form_pg_toastrel) GETSTRUCT(tup))->toastentid, lockmode);
				fs = TupeFitsRelation(testrel, tuplesize);
				tkey->attnum = fs;
				table_close(testrel, lockmode);
				if(fs >= tuplesize)
				{
					tkey->toastentid = ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid;
					tkey->attnum = ((Form_pg_toastrel) GETSTRUCT(tup))->attnum;
					break;
				}
//				else continue;
			}

			if( ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid >= keys )
			{
				keys = ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid;
				/* XXX trel_oid = ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid; */
				tkey->toastentid = ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid;
				tkey->attnum = ((Form_pg_toastrel) GETSTRUCT(tup))->attnum;
				break;
			}
		}
	}

	systable_endscan(scan);
	table_close(pg_toastrel, lockmode);
/*
	MemoryContextSwitchTo(oldctx);
*/
	return PointerGetDatum(tkey); /* ObjectIdGetDatum(trel_oid); */
}

/* ----------
 * GetRelColToasterOid -
 *
 *	Retrieve single TOAST relation from pg_toastrel according to
 *	given key. If not found create a new one
 * ----------
 */
Datum
GetRelColToasterOid(Oid relid, Oid toasteroid, int16 attnum, LOCKMODE lockmode)
{
	Relation		pg_toaster_rel;
	ScanKeyData key[3];
	SysScanDesc scan;
	HeapTuple	tup;
	uint32      total_entries = 0;
	int keys = 0;
	Oid			tsr_oid = InvalidOid;
	int version = 0;
	Toastkey	tkey;

	tkey = palloc(sizeof(ToastrelKey));
	tkey->toastentid = InvalidOid;
	tkey->attnum = -1;

	elog(NOTICE, "GetRelColToasterOid relid %u tentid %u attnum %u",
			 relid, toastentid, attnum);

	pg_toaster_rel = table_open(ToasterRelKeyIndexId, lockmode);

	ScanKeyInit(&key[keys],
				Anum_pg_toaster_rel_relid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(relid));
	keys++;

	if(toasteroid != InvalidOid)
	{
		ScanKeyInit(&key[keys],
			Anum_pg_toaster_rel_toasteroid,
			BTEqualStrategyNumber, F_OIDEQ,
			ObjectIdGetDatum(toasteroid));
	}
	else
	{
		ScanKeyInit(&key[keys],
			Anum_pg_toaster_rel_toasteroid,
			BTEqualStrategyNumber, F_OIDEQ,
			(Datum) 0);
	}
	keys++;

	ScanKeyInit(&key[keys],
				Anum_pg_toaster_rel_attnum,
				BTEqualStrategyNumber, F_INT2EQ,
				Int16GetDatum(attnum));
	keys++;

	scan = systable_beginscan(pg_toaster_rel, ToasterRelKeyIndexId, false,
							  NULL, keys, key);
	keys = 0;
	elog(NOTICE, "Cycle start");
	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		total_entries++;
		elog(NOTICE, "Found TOAST toasterid %u relid %u attnum %u version %u",
			 ((Form_pg_toaster_rel) GETSTRUCT(tup))->toasteroid,
			 ((Form_pg_toaster_rel) GETSTRUCT(tup))->relid,
			 ((Form_pg_toaster_rel) GETSTRUCT(tup))->attnum,
			 ((Form_pg_toaster_rel) GETSTRUCT(tup))->version);

		if((((Form_pg_toaster_rel) GETSTRUCT(tup))->relid == relid )
			&& ((Form_pg_toaster_rel) GETSTRUCT(tup))->attnum == attnum )
		{
			if(((Form_pg_toaster_rel) GETSTRUCT(tup))->version >= version)
			{
				version = ((Form_pg_toaster_rel) GETSTRUCT(tup))->version;
				tkey->attnum = ((Form_pg_toaster_rel) GETSTRUCT(tup))->version;
				tkey->toastentid = ((Form_pg_toaster_rel) GETSTRUCT(tup))->toasteroid;
			}
		}
	}

	tkey->attnum++;

	systable_endscan(scan);
	table_close(pg_toaster_rel, lockmode);
	return PointerGetDatum(tkey);
}

/* ----------
 * GetRelColToasterOid -
 *
 *	Retrieve single TOAST relation from pg_toastrel according to
 *	given key. If not found create a new one
 * ----------
 */
Datum
GetToasterRelToasterOid(Oid relid, Oid toasteroid, int16 attnum, int16 version, LOCKMODE lockmode)
{
	Relation		pg_toaster_rel;
	ScanKeyData key[4];
	SysScanDesc scan;
	HeapTuple	tup;
	uint32      total_entries = 0;
	int keys = 0;
	Oid			tsr_oid = InvalidOid;
	Toastkey	tkey;

	tkey = palloc(sizeof(ToastrelKey));
	tkey->toastentid = InvalidOid;
	tkey->attnum = -1;

	elog(NOTICE, "GetToasterRelToasterOid relid %u tentid %u attnum %u",
			 relid, toasteroid, attnum);

	pg_toaster_rel = table_open(ToasterRelRelationId, lockmode);

	ScanKeyInit(&key[keys],
				Anum_pg_toaster_rel_relid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(relid));
	keys++;

	ScanKeyInit(&key[keys],
		Anum_pg_toaster_rel_toasteroid,
		BTEqualStrategyNumber, F_OIDEQ,
		ObjectIdGetDatum(toasteroid));
	keys++;

	ScanKeyInit(&key[keys],
				Anum_pg_toaster_rel_attnum,
				BTEqualStrategyNumber, F_INT2EQ,
				Int16GetDatum(attnum));
	keys++;

	scan = systable_beginscan(pg_toaster_rel, ToasterRelKeyIndexId, false,
							  NULL, keys, key);
	keys = 0;
	elog(NOTICE, "Cycle start");
	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		total_entries++;
		elog(NOTICE, "Found TOAST toasterid %u relid %u toastent %u attnum %u",
			 ((Form_pg_toaster_rel) GETSTRUCT(tup))->toasteroid,
			 ((Form_pg_toaster_rel) GETSTRUCT(tup))->relid,
			 ((Form_pg_toaster_rel) GETSTRUCT(tup))->version,
			 ((Form_pg_toaster_rel) GETSTRUCT(tup))->attnum);

		if((((Form_pg_toaster_rel) GETSTRUCT(tup))->relid == relid )
			&& ((Form_pg_toaster_rel) GETSTRUCT(tup))->attnum == attnum )
		{
			if(((Form_pg_toaster_rel) GETSTRUCT(tup))->version >= tkey->attnum)
			{
				tkey->attnum = ((Form_pg_toaster_rel) GETSTRUCT(tup))->version;
				tkey->toastentid = ((Form_pg_toaster_rel) GETSTRUCT(tup))->toasteroid;
			}
		}
	}

	tkey->attnum++;

	systable_endscan(scan);
	table_close(pg_toaster_rel, lockmode);
	return PointerGetDatum(tkey);
}

/* ----------
 * InsertToastRelation -
 *
 *	Insert single TOAST relation into pg_toastrel
 * ----------
 */
bool
InsertToastRelation(Oid toasterrelid, Oid relid, Oid toastentid, int16 attnum,
	int version, NameData relname, NameData toastentname, char toastoptions, LOCKMODE lockmode)
{
	Relation		pg_toastrel;
	HeapTuple	tup;
	Datum		values[Natts_pg_toastrel];
	bool		nulls[Natts_pg_toastrel];

	if (toasterrelid == InvalidOid || relid == InvalidOid) /* || toastentid == InvalidOid) */
	{
		return false;
	}

	memset(nulls, false, sizeof(nulls));

	pg_toastrel = table_open(ToastrelRelationId, lockmode);
	{
		Oid			oid = GetNewOidWithIndex(pg_toastrel, ToastrelOidIndexId,
											 Anum_pg_toastrel_oid);

		values[Anum_pg_toastrel_oid - 1] = ObjectIdGetDatum(oid);
		values[Anum_pg_toastrel_toasterrelid - 1] = ObjectIdGetDatum(toasterrelid);
		values[Anum_pg_toastrel_relid - 1] = ObjectIdGetDatum(relid);
		values[Anum_pg_toastrel_toastentid - 1] = ObjectIdGetDatum(toastentid);
		values[Anum_pg_toastrel_attnum - 1] = Int16GetDatum(attnum);
		values[Anum_pg_toastrel_relname - 1] = NameGetDatum(&relname);
		values[Anum_pg_toastrel_version - 1] = Int16GetDatum(version);
		values[Anum_pg_toastrel_toastentname - 1] = NameGetDatum(&toastentname);
		values[Anum_pg_toastrel_toastoptions - 1] = CharGetDatum(toastoptions);
		values[Anum_pg_toastrel_sys_creation_date - 1] = TimestampGetDatum(GetCurrentTimestamp());

		tup = heap_form_tuple(RelationGetDescr(pg_toastrel), values, nulls);

		elog(NOTICE, "Insert into pg_toastrel toasterid %u relid %u toastent %u attnum %u version %u",
			 toasteroid,
			 relid,
			 toastentid,
			 attnum,
			 version);

		CatalogTupleInsert(pg_toastrel, tup);
		heap_freetuple(tup);
	}
	table_close(pg_toastrel, lockmode);
	CommandCounterIncrement();
	return true;
}

/* ----------
 * InsertToasterRelRelation -
 *
 *	Insert single TOAST relation into pg_toaster_rel
 * ----------
 */
Oid
InsertToasterRelRelation(Oid toasteroid, Oid relid, int16 attnum,
	int version, text *toastoptions, LOCKMODE lockmode)
{
	Relation		pg_toaster_rel;
	HeapTuple	tup;
	Datum		values[Natts_pg_toaster_rel];
	bool		nulls[Natts_pg_toaster_rel];

	memset(nulls, false, sizeof(nulls));

	pg_toaster_rel = table_open(ToasterRelRelationId, lockmode);
	{
		Oid			oid = GetNewOidWithIndex(pg_toaster_rel, ToasterRelOidIndexId,
											 Anum_pg_toaster_rel_oid);

		values[Anum_pg_toaster_rel_oid - 1] = ObjectIdGetDatum(oid);
		values[Anum_pg_toaster_rel_toasteroid - 1] = ObjectIdGetDatum(toasteroid);
		values[Anum_pg_toaster_rel_relid - 1] = ObjectIdGetDatum(relid);
		values[Anum_pg_toaster_rel_attnum - 1] = Int16GetDatum(attnum);
		values[Anum_pg_toaster_rel_version - 1] = Int16GetDatum(version);
		values[Anum_pg_toaster_rel_toastoptions - 1] = CStringGetDatum(text_to_cstring(toastoptions));
		values[Anum_pg_toaster_rel_sys_creation_date - 1] = TimestampGetDatum(GetCurrentTimestamp());

		tup = heap_form_tuple(RelationGetDescr(pg_toaster_rel), values, nulls);

		elog(NOTICE, "Insert into pg_toaster_rel toasterid %u relid %u attnum %u version %u",
			 toasteroid,
			 relid,
			 attnum,
			 version);

		CatalogTupleInsert(pg_toaster_rel, tup);
		heap_freetuple(tup);
	}
	CommandCounterIncrement();
	table_close(pg_toaster_rel, lockmode);
	return true;
}

/* ----------
 * InsertToastRelation -
 *
 *	Insert single TOAST relation into pg_toastrel
 * ----------
 */
Datum
CheckAndInsertToastRelation(Oid toasteroid, Oid relid, Oid toastentid, int16 attnum,
	int version, NameData relname, NameData toastentname, char toastoptions, LOCKMODE lockmode)
{
	Relation		pg_toastrel;
	HeapTuple	tup;
	Datum		values[Natts_pg_toastrel];
	bool		nulls[Natts_pg_toastrel];

	if (toasteroid == InvalidOid || relid == InvalidOid)
	{
		return false;
	}

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
		values[Anum_pg_toastrel_relname - 1] = NameGetDatum(&relname);
		values[Anum_pg_toastrel_version - 1] = Int16GetDatum(version);
		values[Anum_pg_toastrel_toastentname - 1] = NameGetDatum(&toastentname);
		values[Anum_pg_toastrel_toastoptions - 1] = CharGetDatum(toastoptions);

		tup = heap_form_tuple(RelationGetDescr(pg_toastrel), values, nulls);

		elog(NOTICE, "Insert into pg_toastrel toasterid %u relid %u toastent %u attnum %u version %u",
			 toasteroid,
			 relid,
			 toastentid,
			 attnum,
			 version);

		CatalogTupleInsert(pg_toastrel, tup);
		heap_freetuple(tup);
	}
	table_close(pg_toastrel, lockmode);
	CommandCounterIncrement();
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

/* Look if the relation has enough free space to fit tuple */
int
TupeFitsRelation(Relation rel, int32 tuple_size)
{
	BlockNumber scanned,
				nblocks,
				blkno;
	Buffer		vmbuffer = InvalidBuffer;
	BufferAccessStrategy bstrategy;
	TransactionId OldestXmin;
	int32	totalfreespace = 0;
	uint64		tuple_len;
	bool fit_ind = false;
	OldestXmin = GetOldestNonRemovableTransactionId(rel);
	bstrategy = GetAccessStrategy(BAS_BULKREAD);

	nblocks = RelationGetNumberOfBlocks(rel);

	if(nblocks*BLCKSZ < F_MAX_INT2 - tuple_size)
		return F_MAX_INT2 - tuple_size; //true;

	scanned = 0;
	elog(NOTICE,"Rel scan %u for size %u", rel->rd_rel->oid, tuple_size);
	for (blkno = 0; blkno < nblocks; blkno++)
	{
		Buffer		buf;
		Page		page;
		OffsetNumber offnum,
					maxoff;
		Size		freespace;

		CHECK_FOR_INTERRUPTS();

		elog(NOTICE,"Block n %u", blkno);
		/*
		 * If the page has only visible tuples, then we can find out the free
		 * space from the FSM and move on.
		 */
		if (VM_ALL_VISIBLE(rel, blkno, &vmbuffer))
		{
			freespace = GetRecordedFreeSpace(rel, blkno);
			tuple_len += BLCKSZ - freespace;
			totalfreespace += freespace;
			continue;
		}

		buf = ReadBufferExtended(rel, MAIN_FORKNUM, blkno,
								 RBM_NORMAL, bstrategy);

		LockBuffer(buf, BUFFER_LOCK_SHARE);

		page = BufferGetPage(buf);

		/*
		 * It's not safe to call PageGetHeapFreeSpace() on new pages, so we
		 * treat them as being free space for our purposes.
		 */
		if (!PageIsNew(page))
			totalfreespace += PageGetHeapFreeSpace(page);
		else
			totalfreespace += BLCKSZ - SizeOfPageHeaderData;

		/* We may count the page as scanned even if it's new/empty */
		scanned++;

		if (PageIsNew(page) || PageIsEmpty(page))
		{
			UnlockReleaseBuffer(buf);
			continue;
		}

		UnlockReleaseBuffer(buf);
		if( totalfreespace >= tuple_size )
		{
			fit_ind = true;
			break;
		}
	}

	if (BufferIsValid(vmbuffer))
	{
		ReleaseBuffer(vmbuffer);
		vmbuffer = InvalidBuffer;
	}
	elog(NOTICE,"FS %u", totalfreespace);
/*
	if(totalfreespace >= tuple_size) return true;
	else return false;
*/
	return totalfreespace;
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

	defList = lappend(defList, makeDefElem("toasteroid", (Node *) makeInteger(toasterid), -1));
	defList = lappend(defList, makeDefElem("toastrelid", (Node *) makeInteger(relid), -1));

	toast_options = transformRelOptions(reloptions,
									 defList, NULL, validnsps, false,
									 false);

	(void) heap_reloptions(RELKIND_TOASTVALUE, toast_options, false);
	return toast_options;
}