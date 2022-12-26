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
	Oid 		relid;
	int16 	attnum;
	Toastrel	tkey;
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

/* Get actual TOAST Rel for table and toaster */
Datum
GetActualToastrel(Oid toasterid, Oid relid, int16 attnum, LOCKMODE lockmode)
{
	Relation		pg_toastrel;
	ScanKeyData key[2];
	SysScanDesc scan;
	HeapTuple	tup;
	uint32      total_entries = 0;
	int keys = 0;
	Toastkey		tkey;
	Oid			trel = InvalidOid;

	tkey = palloc(sizeof(ToastrelKey));
	tkey->toastentid = InvalidOid;
	tkey->toasterid = InvalidOid;
	tkey->attnum = 0;
	tkey->version = 0;

	pg_toastrel = table_open(ToastrelRelationId, lockmode);

	ScanKeyInit(&key[keys],
			Anum_pg_toastrel_relid,
			BTEqualStrategyNumber, F_OIDEQ,
			ObjectIdGetDatum(relid));
	keys++;

	ScanKeyInit(&key[keys],
			Anum_pg_toastrel_attnum,
			BTEqualStrategyNumber, F_INT2EQ,
			Int16GetDatum(attnum));
	keys++;

	scan = systable_beginscan(pg_toastrel, ToastrelRelIndexId, false,
							  NULL, keys, key);
	keys = 0;
	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		total_entries++;
		if(((Form_pg_toastrel) GETSTRUCT(tup))->toasteroid == toasterid
			&& ((Form_pg_toastrel) GETSTRUCT(tup))->version >= tkey->version)
		{
			keys = ((Form_pg_toastrel) GETSTRUCT(tup))->version;
			tkey->toasterid = ((Form_pg_toastrel) GETSTRUCT(tup))->toasteroid;
			tkey->toastentid = ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid;
			tkey->attnum = ((Form_pg_toastrel) GETSTRUCT(tup))->attnum;
			tkey->version = ((Form_pg_toastrel) GETSTRUCT(tup))->version;
			trel = ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid;
		}
	}

	systable_endscan(scan);

	if(trel == InvalidOid)
	{
		keys = 0;
		ScanKeyInit(&key[keys],
			Anum_pg_toastrel_relid,
			BTEqualStrategyNumber, F_OIDEQ,
			ObjectIdGetDatum(relid));
		keys++;

		tkey->version = 0;

		scan = systable_beginscan(pg_toastrel, ToastrelRelIndexId, false,
						  NULL, keys, key);

		while (HeapTupleIsValid(tup = systable_getnext(scan)))
		{
			total_entries++;
			if(((Form_pg_toastrel) GETSTRUCT(tup))->toasteroid == toasterid
				&& ((Form_pg_toastrel) GETSTRUCT(tup))->version >= tkey->version)
			{
				keys = ((Form_pg_toastrel) GETSTRUCT(tup))->version;
				tkey->toasterid = ((Form_pg_toastrel) GETSTRUCT(tup))->toasteroid;
				tkey->toastentid = ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid;
				tkey->attnum = ((Form_pg_toastrel) GETSTRUCT(tup))->attnum;
				tkey->version = ((Form_pg_toastrel) GETSTRUCT(tup))->version;
				trel = ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid;
			}
		}

		systable_endscan(scan);
	}
	table_close(pg_toastrel, lockmode);
	pfree(tkey);

	return ObjectIdGetDatum(trel);
}
/**/

/* Get last assigned TOAST Rel for table and toaster */
Datum
GetLastToaster(Oid relid, int16 attnum, LOCKMODE lockmode)
{
	Relation		pg_toastrel;
	ScanKeyData key[2];
	SysScanDesc scan;
	HeapTuple	tup;
	uint32      total_entries = 0;
	int keys = 0;
	Oid			toaster = InvalidOid;

	pg_toastrel = table_open(ToastrelRelationId, lockmode);

	ScanKeyInit(&key[keys],
			Anum_pg_toastrel_relid,
			BTEqualStrategyNumber, F_OIDEQ,
			ObjectIdGetDatum(relid));
	keys++;

	ScanKeyInit(&key[keys],
			Anum_pg_toastrel_attnum,
			BTEqualStrategyNumber, F_INT2EQ,
			Int16GetDatum(attnum));
	keys++;

	scan = systable_beginscan(pg_toastrel, ToastrelRelIndexId, false,
							  NULL, keys, key);
	keys = 0;
	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		total_entries++;
		if(((Form_pg_toastrel) GETSTRUCT(tup))->version >= keys)
		{
			keys = ((Form_pg_toastrel) GETSTRUCT(tup))->version;
			toaster = ((Form_pg_toastrel) GETSTRUCT(tup))->toasteroid;
		}
	}

	systable_endscan(scan);

	table_close(pg_toastrel, lockmode);

	return ObjectIdGetDatum(toaster); // PointerGetDatum(tkey);
}

/*
 * GetAttVersionToastrel - retrieves last VERSION for Toaster
 * from pg_toastrel
*/
Datum
GetAttVersionToastrel(Oid toasterid, Oid relid, int16 attnum, LOCKMODE lockmode)
{
	Relation		pg_toastrel;
	ScanKeyData key[2];
	SysScanDesc scan;
	HeapTuple	tup;
	uint32      total_entries = 0;
	int keys = 0;
	Oid			version = 1;

	pg_toastrel = table_open(ToastrelRelationId, lockmode);

	ScanKeyInit(&key[keys],
			Anum_pg_toastrel_relid,
			BTEqualStrategyNumber, F_OIDEQ,
			ObjectIdGetDatum(relid));
	keys++;

	ScanKeyInit(&key[keys],
			Anum_pg_toastrel_attnum,
			BTEqualStrategyNumber, F_INT2EQ,
			Int16GetDatum(attnum));
	keys++;

	scan = systable_beginscan(pg_toastrel, ToastrelRelIndexId, false,
							  NULL, keys, key);
	keys = 0;

	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		total_entries++;
		if(toasterid != InvalidOid)
		{
			if(((Form_pg_toastrel) GETSTRUCT(tup))->toasteroid == toasterid
				&& ((Form_pg_toastrel) GETSTRUCT(tup))->version >= version)
			{
				version = ((Form_pg_toastrel) GETSTRUCT(tup))->version;
			}
		}
		else if(((Form_pg_toastrel) GETSTRUCT(tup))->version >= version)
		{
			version = ((Form_pg_toastrel) GETSTRUCT(tup))->version;
		}
	}

	systable_endscan(scan);

	table_close(pg_toastrel, lockmode);

	return Int16GetDatum(version);
}

/* ----------
 * GetFullToastrel -
 *
 *	Retrieves single TOAST relation from pg_toastrel according to
 *	given key.
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
	int keys = 0;
	int16 version = 0;
	Toastrel		tkey;

	tkey = palloc(sizeof(ToastrelData));
	tkey->toastentid = InvalidOid;
	tkey->toasteroid = InvalidOid;
	tkey->attnum = 0;
	tkey->version = 0;

	pg_toastrel = table_open(ToastrelRelationId, lockmode);

	ScanKeyInit(&key[keys],
			Anum_pg_toastrel_relid,
			BTEqualStrategyNumber, F_OIDEQ,
			ObjectIdGetDatum(relid));
	keys++;
/*
	ScanKeyInit(&key[keys],
			Anum_pg_toastrel_attnum,
			BTEqualStrategyNumber, F_INT2EQ,
			Int16GetDatum(attnum));
	keys++;
*/
	scan = systable_beginscan(pg_toastrel, ToastrelRelIndexId, false,
							  NULL, keys, key);
	keys = 0;
	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		total_entries++;
		if(((Form_pg_toastrel) GETSTRUCT(tup))->version >= version )
		{
				keys = ((Form_pg_toastrel) GETSTRUCT(tup))->version;
				tkey->oid = ((Form_pg_toastrel) GETSTRUCT(tup))->oid;
				tkey->toastentid = ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid;
				tkey->version = ((Form_pg_toastrel) GETSTRUCT(tup))->version;
				tkey->attnum = ((Form_pg_toastrel) GETSTRUCT(tup))->attnum;
				tkey->relid = ((Form_pg_toastrel) GETSTRUCT(tup))->relid;
				tkey->toasteroid = ((Form_pg_toastrel) GETSTRUCT(tup))->toasteroid;
				tkey->toastoptions = ((Form_pg_toastrel) GETSTRUCT(tup))->toastoptions;
		}
	}

	systable_endscan(scan);
	table_close(pg_toastrel, lockmode);

	return PointerGetDatum(tkey);
}

/* ----------
 * InsertToastRelation -
 *
 *	Insert single TOAST relation into pg_toastrel.
 * pg_toastrel is searched for existing record for given attribute and Toaster.
 * If record is found - existing TOAST relation is returned, otherwise new record
 * is inserted into pg_toastrel.
 * Field 'version' sets attribute TOAST version - it is incremented with each Toaster
 * set to attribute. Initial value is 0 when no TOAST entity is assigned to attribute,
 * or 1 when it is present.
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
	int16 cversion = 0;
	Oid trel;

	if (toasteroid == InvalidOid || relid == InvalidOid) // || toastentid == InvalidOid)
	{
		return false;
	}
	trel = DatumGetObjectId(GetActualToastrel(toasteroid, relid, attnum, AccessShareLock));
	cversion = DatumGetInt16(GetAttVersionToastrel(InvalidOid, relid, attnum, AccessShareLock));
	if(trel != InvalidOid)
	{
		int16 tversion = DatumGetInt16(GetAttVersionToastrel(toasteroid, relid, attnum, AccessShareLock));
		if(tversion == cversion)
			return true;
	}

	if(!(toastentid == InvalidOid && cversion == 0))
		cversion = cversion + 1;

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
		values[Anum_pg_toastrel_version - 1] = Int16GetDatum(cversion);
		values[Anum_pg_toastrel_relname - 1] = NameGetDatum(&relname);
		values[Anum_pg_toastrel_toastentname - 1] = NameGetDatum(&toastentname);
		values[Anum_pg_toastrel_toastoptions - 1] = CharGetDatum(toastoptions);
		values[Anum_pg_toastrel_flag - 1] = CharGetDatum(0);

		tup = heap_form_tuple(RelationGetDescr(pg_toastrel), values, nulls);
		CatalogTupleInsert(pg_toastrel, tup);
		heap_freetuple(tup);
	}

	table_close(pg_toastrel, lockmode);
	CommandCounterIncrement();
	return true;
}

/* ----------
 * GetToastrelList -
 *
 *	Retrieves PG_TOASTREL toast entities OIDs according to given key
 * ----------
 */
Datum
GetToastrelList(List *trel_list, Oid relid, int16 attnum, LOCKMODE lockmode)
{
	Relation		pg_toastrel;
	ScanKeyData key[4];
	SysScanDesc scan;
	HeapTuple	tup;
	uint32      total_entries = 0;
	int keys = 0;

	pg_toastrel = table_open(ToastrelRelationId, lockmode);

	ScanKeyInit(&key[keys],
			Anum_pg_toastrel_relid,
			BTEqualStrategyNumber, F_OIDEQ,
			ObjectIdGetDatum(relid));
	keys++;

	if(attnum > 0)
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
	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		total_entries++;
		if(((Form_pg_toastrel) GETSTRUCT(tup))->flag != 'x' 
			&& ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid != InvalidOid)
		{
			if(!list_member_oid(trel_list, ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid))
				trel_list = lcons_oid(((Form_pg_toastrel) GETSTRUCT(tup))->toastentid, trel_list);
		}
	}
	systable_endscan(scan);
	table_close(pg_toastrel, lockmode);

	return PointerGetDatum(trel_list);
}

/* ----------
 * GetFullToastrelList -
 *
 *	Retrieves list of PG_TOASTREL rows according to given key
 * ----------
 */
Datum
GetFullToastrelList(List *trel_list, Oid relid, int16 attnum, LOCKMODE lockmode)
{
	Relation		pg_toastrel;
	ScanKeyData key[4];
	SysScanDesc scan;
	HeapTuple	tup;
	uint32      total_entries = 0;
	int keys = 0;
	Toastrel		trel;
	Toastrel		tcell;
	ListCell		*lc;
	int del_itms = 0;
	int found_itms = 0;

	pg_toastrel = table_open(ToastrelRelationId, lockmode);

	ScanKeyInit(&key[keys],
			Anum_pg_toastrel_relid,
			BTEqualStrategyNumber, F_OIDEQ,
			ObjectIdGetDatum(relid));
	keys++;

	if(attnum > 0)
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
	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		total_entries++;
		if(((Form_pg_toastrel) GETSTRUCT(tup))->flag != 'x' 
			&& ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid != InvalidOid)
		{
			del_itms = 0;
			found_itms = 0;
			trel = palloc(sizeof(ToastrelData));
	
			trel->toasteroid = ((Form_pg_toastrel) GETSTRUCT(tup))->toasteroid;
			trel->relid = ((Form_pg_toastrel) GETSTRUCT(tup))->relid;
			trel->attnum = ((Form_pg_toastrel) GETSTRUCT(tup))->attnum;
			trel->version = ((Form_pg_toastrel) GETSTRUCT(tup))->version;
			trel->oid = ((Form_pg_toastrel) GETSTRUCT(tup))->oid;
			trel->toastentid = ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid;
			trel->toastoptions = ((Form_pg_toastrel) GETSTRUCT(tup))->toastoptions;

			foreach(lc, trel_list)
			{
				tcell = (Toastrel)lfirst(lc);

				if (tcell->attnum == ((Form_pg_toastrel) GETSTRUCT(tup))->attnum
					&& ((Form_pg_toastrel) GETSTRUCT(tup))->version >= tcell->version)
				{
					del_itms++;
					foreach_delete_current(trel_list, lc);
					break;
				}
				else found_itms++;
			}
			if(found_itms == 0) trel_list = lcons(trel, trel_list);
		}
	}

	systable_endscan(scan);
	table_close(pg_toastrel, lockmode);

	return PointerGetDatum(trel_list);
}

/* ----------
 * HasToastrel -
 *
 *	Checks pg_toastrel if there are TOAST relations for
 *	given Toaster OID, relation OID and attribute index
 * ----------
 */
bool
HasToastrel(Oid toasterid, Oid relid, int16 attnum, LOCKMODE lockmode)
{
	Relation		pg_toastrel;
	ScanKeyData key[4];
	SysScanDesc scan;
	HeapTuple	tup;
	uint32      total_entries = 0;
	int keys = 0;
	bool has_toastrel = false;

	pg_toastrel = table_open(ToastrelRelationId, lockmode);

	if(relid > 0)
	{
		ScanKeyInit(&key[keys],
			Anum_pg_toastrel_relid,
			BTEqualStrategyNumber, F_OIDEQ,
			ObjectIdGetDatum(relid));
		keys++;
	}

	if(toasterid > 0)
	{
		ScanKeyInit(&key[keys],
			Anum_pg_toastrel_toasteroid,
			BTEqualStrategyNumber, F_OIDEQ,
			Int16GetDatum(toasterid));
		keys++;
	}

	if(attnum > 0)
	{
		ScanKeyInit(&key[keys],
			Anum_pg_toastrel_attnum,
			BTEqualStrategyNumber, F_INT2EQ,
			Int16GetDatum(attnum));
		keys++;
	}

	if(keys == 0)
	{
		table_close(pg_toastrel, lockmode);
		return has_toastrel;
	}

	scan = systable_beginscan(pg_toastrel, ToastrelRelIndexId, false,
							  NULL, keys, key);
	keys = 0;
	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		total_entries++;
		if(((Form_pg_toastrel) GETSTRUCT(tup))->flag != 'x' 
			&& ((Form_pg_toastrel) GETSTRUCT(tup))->toastentid != InvalidOid)
		{
			has_toastrel = true;
			break;
		}
	}

	systable_endscan(scan);
	table_close(pg_toastrel, lockmode);

	return has_toastrel;
}


/* ----------
 * DeleteToastRelation -
 *
 *	Removes row from PG_TOASTREL
 */
bool
DeleteToastRelation(Oid treloid, Oid toasteroid, Oid relid, Oid toastentid, int16 attnum,
	int version, LOCKMODE lockmode)
{
	Relation		pg_toastrel;
	ScanKeyData key[4];
	SysScanDesc scan;
	HeapTuple	tup;
	int keys = 0;

	pg_toastrel = table_open(ToastrelRelationId, lockmode);

	if(treloid != InvalidOid)
	{
		ScanKeyInit(&key[keys],
				Anum_pg_toastrel_toasteroid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(toasteroid));
		keys++;
	}
	else
	{
		if(toasteroid > 0)
		{
			ScanKeyInit(&key[keys],
				Anum_pg_toastrel_toasteroid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(toasteroid));
			keys++;
		}
		if(relid > 0)
		{
			ScanKeyInit(&key[keys],
				Anum_pg_toastrel_relid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(relid));
			keys++;
		}
		if(attnum > 0)
		{
			ScanKeyInit(&key[keys],
				Anum_pg_toastrel_attnum,
				BTEqualStrategyNumber, F_INT2EQ,
				Int16GetDatum(attnum));
			keys++;
		}
		if(version > 0)
		{
			ScanKeyInit(&key[keys],
				Anum_pg_toastrel_version,
				BTEqualStrategyNumber, F_INT2EQ,
				Int16GetDatum(version));
			keys++;
		}
	}

	if(treloid != InvalidOid)
	{
		scan = systable_beginscan(pg_toastrel, ToastrelOidIndexId, true,
							  NULL, keys, key);
	}
	else
	{
		scan = systable_beginscan(pg_toastrel, ToastrelKeyIndexId, true,
							  NULL, keys, key);
	}

	while (HeapTupleIsValid((tup = systable_getnext(scan))))
	{
		CatalogTupleDelete(pg_toastrel, &tup->t_self);
	}

	systable_endscan(scan);
	table_close(pg_toastrel, lockmode);
	CommandCounterIncrement();
	return true;
}

/* ----------
 * UpdateToastRelationFlag -
 *
 *	Updates pg_toastrel record field with passed value. Used to set pg_toastrel
 * row to not actual (for deleted Toasters)
 * ----------
 */
bool
UpdateToastRelationFlag(Oid treloid, Oid toasteroid, Oid relid, Oid toastentid, int16 attnum,
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

	memset(nulls, false, sizeof(nulls));

	pg_toastrel = table_open(ToastrelRelationId, lockmode);

	if(treloid != InvalidOid)
	{
		ScanKeyInit(&key[keys],
				Anum_pg_toastrel_toasteroid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(toasteroid));
		keys++;
	}
	else
	{
		if(toasteroid > 0)
		{
			ScanKeyInit(&key[keys],
				Anum_pg_toastrel_toasteroid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(toasteroid));
			keys++;
		}
		if(relid > 0)
		{
			ScanKeyInit(&key[keys],
				Anum_pg_toastrel_relid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(relid));
			keys++;
		}
		if(attnum > 0)
		{
			ScanKeyInit(&key[keys],
				Anum_pg_toastrel_attnum,
				BTEqualStrategyNumber, F_INT2EQ,
				Int16GetDatum(attnum));
			keys++;
		}
		if(version > 0)
		{
			ScanKeyInit(&key[keys],
				Anum_pg_toastrel_version,
				BTEqualStrategyNumber, F_INT2EQ,
				Int16GetDatum(version));
			keys++;
		}
	}

	if(treloid != InvalidOid)
	{
		scan = systable_beginscan(pg_toastrel, ToastrelOidIndexId, true,
							  NULL, keys, key);
	}
	else
	{
		scan = systable_beginscan(pg_toastrel, ToastrelKeyIndexId, true,
							  NULL, keys, key);
	}

	while (HeapTupleIsValid((tup = systable_getnext(scan))))
	{
		values[Anum_pg_toastrel_flag - 1] = CharGetDatum(flag);
		replaces[Anum_pg_toastrel_flag - 1] = true;

		newtup = heap_modify_tuple(tup, RelationGetDescr(pg_toastrel),
										 values, nulls, replaces);
		CatalogTupleUpdate(pg_toastrel, &newtup->t_self, newtup);

		heap_freetuple(tup);
	}

	systable_endscan(scan);
	table_close(pg_toastrel, lockmode);
	CommandCounterIncrement();
	return true;
}

/*
 * InsertToastrelCache - Simple insert single pg_toastrel record into cache
 */
Datum
InsertToastrelCache(Oid treloid, Oid toasteroid, Oid relid, Oid toastentid, int16 attnum,
	int16 version, char toastoptions)
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
 * DeleteToastrelCache - delete cached pg_toastrel record
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
		if (entry->relid == relid
			&& entry->attnum == attnum
			&& entry->tkey->toasteroid == toasterid)
			return PointerGetDatum(entry->tkey);
	}

	/* didn't find in first position */
	ctx = MemoryContextSwitchTo(CacheMemoryContext);

	for_each_from(lc, ToastrelCache, 0)
	{
		entry = (ToastrelCacheEntry*)lfirst(lc);

		if (entry->relid == relid
			&& entry->attnum == attnum
			&& entry->tkey->toasteroid == toasterid)
		{
			result = PointerGetDatum(entry->tkey);
			foreach_delete_current(ToastrelCache, lc);
			goto out;
		}
	}

out:
	MemoryContextSwitchTo(ctx);

	return result;
}

/*
 * SearchToastrelCache - search cached pg_toastrel record
 * by base relid, attribute index
 */
Datum
SearchToastrelCache(Oid	relid, int16 attnum, bool search_ind)
{
	ListCell		   *lc;
	ToastrelCacheEntry  *entry;
	MemoryContext		ctx;
	Datum result = (Datum) 0;
	Toastrel trel = NULL;
	Toastkey	tkey = NULL;

	if (list_length(ToastrelCache) > 0)
	{
		/* fast path */
		entry = (ToastrelCacheEntry*)linitial(ToastrelCache);
		if (entry->relid == relid
			&& entry->attnum == attnum)
		{
/*
			trel = palloc(sizeof(ToastrelData));
			trel->toasteroid = entry->tkey->toasteroid;
			trel->relid = entry->tkey->relid;
			trel->attnum = entry->tkey->attnum;
			trel->version = entry->tkey->version + 1;
			trel->oid = entry->tkey->oid;
			trel->toastentid = entry->tkey->toastentid;
			trel->toastoptions = entry->tkey->toastoptions;

			return PointerGetDatum(trel);
*/
			return PointerGetDatum(entry->tkey);
		}
	}

	/* didn't find in first position */
	ctx = MemoryContextSwitchTo(CacheMemoryContext);
lookup:
	for_each_from(lc, ToastrelCache, 0)
	{
		entry = (ToastrelCacheEntry*)lfirst(lc);

		if (entry->relid == relid
			&& entry->attnum == attnum)
		{
/*
			trel = palloc(sizeof(ToastrelData));
			trel->toasteroid = entry->tkey->toasteroid;
			trel->relid = entry->tkey->relid;
			trel->attnum = entry->tkey->attnum;
			trel->version = entry->tkey->version + 1;
			trel->oid = entry->tkey->oid;
			trel->toastentid = entry->tkey->toastentid;
			trel->toastoptions = entry->tkey->toastoptions;

			result = PointerGetDatum(trel);
*/
			result = PointerGetDatum(entry->tkey);
			goto out;
		}
	}

	trel = (Toastrel) DatumGetPointer(GetFullToastrel(relid, attnum, AccessShareLock));

	if(trel != NULL && trel->toastentid != InvalidOid)
	{
		tkey = (Toastkey) DatumGetPointer(InsertOrReplaceToastrelCache(trel->oid, trel->toasteroid, relid, trel->toastentid, attnum, 0));
		pfree(tkey);
		goto lookup;
	}

out:
	MemoryContextSwitchTo(ctx);
	return result;
}

/*
 * InsertOrReplaceToastrelCache - Insert new or replace existing cached pg_toastrel record.
 * pg_toastrel contains only actual (last) Toaster record for relation attribute
 */
Datum
InsertOrReplaceToastrelCache(Oid treloid, Oid toasteroid, Oid relid, Oid toastentid, int16 attnum,
	char toastoptions)
{
	ListCell		   *lc;
	ToastrelCacheEntry  *entry;
	MemoryContext		ctx;
	int version = 0;
	Toastkey tkey = NULL;

	ctx = MemoryContextSwitchTo(CacheMemoryContext);
	
	if (list_length(ToastrelCache) > 0)
	{
		entry = (ToastrelCacheEntry*)linitial(ToastrelCache);
		if (entry->relid != relid && entry->attnum != attnum)
		{
			for_each_from(lc, ToastrelCache, 0)
			{
				entry = (ToastrelCacheEntry*)lfirst(lc);

				if (entry->relid == relid
					&& entry->attnum == attnum)
				{
					version = entry->tkey->version;
					pfree(entry->tkey);
					foreach_delete_current(ToastrelCache, lc);
					break;
				}
			}
		}
	}

	entry = palloc(sizeof(ToastrelCacheEntry));
	entry->tkey = palloc(sizeof(ToastrelData));
	
	entry->tkey->toasteroid = toasteroid;
	entry->tkey->relid = relid;
	entry->tkey->attnum = attnum;
	entry->tkey->version = version + 1;
	entry->tkey->oid = treloid;
	entry->tkey->toastentid = toastentid;
	entry->tkey->toastoptions = toastoptions;

	entry->relid = relid;
	entry->attnum = attnum;

	tkey = palloc(sizeof(ToastrelKey));
	tkey->version = entry->tkey->version;
	tkey->attnum = entry->tkey->attnum;
	tkey->toastentid = toastentid;
	tkey->toasterid = toasteroid;

	ToastrelCache = lcons(entry, ToastrelCache);
	MemoryContextSwitchTo(ctx);
	return PointerGetDatum(tkey);
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

Datum
GetInheritedToaster(List *schema, List *supers, char relpersistence,
				bool is_partition, List **supconstr,
				Oid accessMethodId, NameData attname, Oid typid)
{
/*	List	   *inhSchema = NIL;
	int			child_attno; */
	ListCell   *entry;
	Oid tsroid = InvalidOid;

	/*
	 * Scan the parents left-to-right, and merge their attributes to form a
	 * list of inherited attributes (inhSchema).  Also check to see if we need
	 * to inherit an OID column.
	 */
/*	child_attno = 0; */
	foreach(entry, supers)
	{
		Oid			parent = lfirst_oid(entry);
		Relation	relation;
		TupleDesc	tupleDesc;
/*		TupleConstr *constr;
		AttrMap    *newattmap; */
		AttrNumber	parent_attno;

		/* caller already got lock */
		relation = table_open(parent, NoLock);

		tupleDesc = RelationGetDescr(relation);
/*		constr = tupleDesc->constr; */

		for (parent_attno = 1; parent_attno <= tupleDesc->natts;
			 parent_attno++)
		{
			Form_pg_attribute attribute = TupleDescAttr(tupleDesc,
														parent_attno - 1);
/*			char	   *attributeName = NameStr(attribute->attname); */

			if (attribute->attisdropped)
				continue;

			if(strcmp(NameStr(attribute->attname), NameStr(attname))
				&& typid == attribute->atttypid)
			{
				tsroid = DatumGetObjectId(GetLastToaster(relation->rd_id, attribute->attnum, AccessShareLock));

				if (OidIsValid(tsroid))
				{
					if(!validateToaster(tsroid, attribute->atttypid,
									attribute->attstorage, attribute->attcompression,
									accessMethodId, false))
						tsroid = InvalidOid;
				}
			}
		}

		table_close(relation, NoLock);
	}
/*
	if (inhSchema != NIL)
	{
		int			schema_attno = 0;

		foreach(entry, schema)
		{
			ColumnDef  *newdef = lfirst(entry);
			char	   *attributeName = newdef->colname;
			int			exist_attno;

			schema_attno++;

			exist_attno = findAttrByName(attributeName, inhSchema);
			if (exist_attno > 0)
			{
				ColumnDef  *def;
				Oid			defTypeId,
							newTypeId;
				int32		deftypmod,
							newtypmod;
				Oid			defcollid,
							newcollid;

				Assert(!is_partition);

				if (exist_attno == schema_attno)
					ereport(NOTICE,
							(errmsg("merging column \"%s\" with inherited definition",
									attributeName)));
				else
					ereport(NOTICE,
							(errmsg("moving and merging column \"%s\" with inherited definition", attributeName),
							 errdetail("User-specified column moved to the position of the inherited column.")));
				def = (ColumnDef *) list_nth(inhSchema, exist_attno - 1);
				typenameTypeIdAndMod(NULL, def->typeName, &defTypeId, &deftypmod);
				typenameTypeIdAndMod(NULL, newdef->typeName, &newTypeId, &newtypmod);
				if (defTypeId != newTypeId || deftypmod != newtypmod)
					ereport(ERROR,
							(errcode(ERRCODE_DATATYPE_MISMATCH),
							 errmsg("column \"%s\" has a type conflict",
									attributeName),
							 errdetail("%s versus %s",
									   format_type_with_typemod(defTypeId,
																deftypmod),
									   format_type_with_typemod(newTypeId,
																newtypmod))));

				if (def->storage == 0)
					def->storage = newdef->storage;
				else if (newdef->storage != 0 && def->storage != newdef->storage)
					ereport(ERROR,
							(errcode(ERRCODE_DATATYPE_MISMATCH),
							 errmsg("column \"%s\" has a storage parameter conflict",
									attributeName),
							 errdetail("%s versus %s",
									   storage_name(def->storage),
									   storage_name(newdef->storage))));

				if (def->toaster == NULL)
					def->toaster = newdef->toaster;
				else if (newdef->toaster != NULL &&
						 strcmp(def->toaster, newdef->toaster) != 0)
					ereport(ERROR,
							(errcode(ERRCODE_DATATYPE_MISMATCH),
							 errmsg("column \"%s\" has a toaster parameter conflict",
									attributeName),
							 errdetail("%s versus %s",
									   def->toaster,
									   newdef->toaster)));

			}
			else
			{
				inhSchema = lappend(inhSchema, newdef);
			}
		}

		schema = inhSchema;

		if (list_length(schema) > MaxHeapAttributeNumber)
			ereport(ERROR,
					(errcode(ERRCODE_TOO_MANY_COLUMNS),
					 errmsg("tables can have at most %d columns",
							MaxHeapAttributeNumber)));
	}
*/
	return tsroid;
}