#include "postgres.h"
#include "varatt.h"
#include "fmgr.h"
#include "toastapi.h"
#include "access/toast_helper.h"

#include "access/htup_details.h"
#include "commands/defrem.h"
#include "lib/pairingheap.h"
#include "utils/builtins.h"
#include "utils/memutils.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "access/heaptoast.h"
#include "access/reloptions.h"
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

#include "catalog/pg_am_d.h"
#include "commands/vacuum.h"
#include "funcapi.h"
#include "storage/bufmgr.h"

#include "libpq/auth.h"
#include "utils/guc.h"
#include "utils/timestamp.h"

#include "utils/lsyscache.h"
#include "utils/regproc.h"

#include "access/toast_internals.h"
#include "access/toast_hook.h"
#include "utils/elog.h"
#include "pg_toaster.h"
#include "pg_toastrel.h"
#include "utils/varlena.h"
#include "varatt_custom.h"
#include "toastapi_internals.h"
#include "toastapi_sqlfuncs.h"

/*
CREATE FUNCTION set_toaster(cstring, cstring, cstring)
RETURNS integer
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION add_toaster(cstring, cstring)
RETURNS integer
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION drop_toaster(cstring)
RETURNS integer
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION get_toaster(cstring, cstring)
RETURNS integer
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION list_toasters(cstring)
RETURNS integer
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION list_toastrels(cstring)
RETURNS integer
AS 'MODULE_PATHNAME'
LANGUAGE C;

*/

Oid insert_toaster(const char *tsrname, const char *tsrhandler)
{
	Relation		pg_toastrel;
	HeapTuple	tup;
	Datum		values[Natts_pg_toastrel];
	bool		nulls[Natts_pg_toastrel];
	bool		found = false;
	List	   *indexlist;
	ListCell   *lc;
	Relation rel;
	int num_indexes = 0;
	Relation relindx;
	Oid relid = InvalidOid;
	Oid idx_oid = InvalidOid;

	ScanKeyData key[2];
	SysScanDesc scan;
	uint32      total_entries = 0;
	int keys = 0;
	Oid tsroid = InvalidOid;

	Relation pg_toaster = get_rel_from_relname(cstring_to_text(pg_toaster_name), RowExclusiveLock, ACL_INSERT);

	indexlist = RelationGetIndexList(pg_toaster);
	
	Assert(indexlist != NIL);

	num_indexes = list_length(indexlist);

	foreach(lc, indexlist)
	{
		relindx = index_open(lfirst_oid(lc), AccessShareLock);
		idx_oid = RelationGetRelid(relindx);
		index_close(relindx, AccessShareLock);
		found = true;
		break;
	}

	list_free(indexlist);

	if (!found)
	{
		table_close(pg_toaster, RowExclusiveLock);
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_FUNCTION),
				 errmsg("no valid index found for toast relation with Oid %u", relid)));
	}

	ScanKeyInit(&key[keys],
			Anum_pg_toaster_tsrname,
			BTEqualStrategyNumber, F_TEXTEQ,
			CStringGetDatum(tsrname));
	keys++;

	scan = systable_beginscan(pg_toaster, idx_oid, false,
							  NULL, keys, key);
	keys = 0;
	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		total_entries++;
		tsroid = ((Form_pg_toaster) GETSTRUCT(tup))->oid;
		break;
	}
	systable_endscan(scan);
	table_close(pg_toastrel, RowExclusiveLock);
	if(OidIsValid(tsroid))
	{
		table_close(pg_toaster, RowExclusiveLock);
		return tsroid;
	}
	{
		tsroid = GetNewOidWithIndex(pg_toaster, idx_oid,
											 Anum_pg_toaster_oid);

		values[Anum_pg_toaster_oid - 1] = ObjectIdGetDatum(tsroid);
		values[Anum_pg_toaster_tsrname - 1] = CStringGetDatum(tsrname);
		values[Anum_pg_toaster_tsrhandler - 1] = CStringGetDatum(tsrhandler);

		tup = heap_form_tuple(RelationGetDescr(pg_toaster), values, nulls);
		CatalogTupleInsert(pg_toaster, tup);
		heap_freetuple(tup);
	}

	table_close(pg_toaster, RowExclusiveLock);
	CommandCounterIncrement();
	return tsroid;
}

Oid insert_toastrel(Oid tsroid, Oid relid, Oid toastrelid, int16 attnum, int16 version, char opts, char flag)
{
	Relation		pg_toastrel;
	HeapTuple	tup;
	Datum		values[Natts_pg_toastrel];
	bool		nulls[Natts_pg_toastrel];
	int16 cversion = 0;
	Oid trel;
	Oid			oid;

	pg_toastrel = get_rel_from_relname(cstring_to_text(pg_toastrel_name), RowExclusiveLock, ACL_INSERT);

	{
		oid = GetNewOidWithIndex(pg_toastrel, ToastrelOidIndexId,
											 Anum_pg_toastrel_oid);

		values[Anum_pg_toastrel_oid - 1] = ObjectIdGetDatum(oid);
		values[Anum_pg_toastrel_toasteroid - 1] = ObjectIdGetDatum(tsroid);
		values[Anum_pg_toastrel_relid - 1] = ObjectIdGetDatum(relid);
		values[Anum_pg_toastrel_toastentid - 1] = ObjectIdGetDatum(toastrelid);
		values[Anum_pg_toastrel_attnum - 1] = Int16GetDatum(attnum);
		values[Anum_pg_toastrel_version - 1] = Int16GetDatum(cversion);
		values[Anum_pg_toastrel_toastoptions - 1] = CharGetDatum(opts);
		values[Anum_pg_toastrel_flag - 1] = CharGetDatum(0);

		tup = heap_form_tuple(RelationGetDescr(pg_toastrel), values, nulls);
		CatalogTupleInsert(pg_toastrel, tup);
		heap_freetuple(tup);
	}

	table_close(pg_toastrel, RowExclusiveLock);
	CommandCounterIncrement();
	return oid;
}

void
open_toastapi_index(Relation rel, LOCKMODE lock, Oid *idx_oid)
{
	int			i = 0;
	int			res = 0;
	bool		found = false;
	List	   *indexlist;
	ListCell   *lc;
	int num_indexes = 0;
	Relation **relindxs;
	Oid relid = InvalidOid;

//	rel = get_rel_from_relname(cstring_to_text(relname), AccessShareLock, ACL_SELECT);
	relid = RelationGetRelid(rel);

	indexlist = RelationGetIndexList(rel);
	
	Assert(indexlist != NIL);

	num_indexes = list_length(indexlist);

	*relindxs = (Relation *) palloc(num_indexes * sizeof(Relation));
	foreach(lc, indexlist)
		(*relindxs)[i++] = index_open(lfirst_oid(lc), lock);

	for (i = 0; i < num_indexes; i++)
	{
		Relation	toastidx = (*relindxs)[i];

		if (toastidx->rd_index->indisvalid)
		{
			res = i;
			found = true;
			*idx_oid = RelationGetRelid(toastidx);
			break;
		}
	}

	list_free(indexlist);

	if (!found)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_FUNCTION),
				 errmsg("no valid index found for toast relation with Oid %u", relid)));
}


PG_FUNCTION_INFO_V1(add_toaster);

Datum
add_toaster(PG_FUNCTION_ARGS)
{
	Relation	toastrel;
	Relation	rel;
	Relation   *toastidxs;
	Relation   relindx;
	Oid			idx_oid;
	int			num_indexes;
	int			validIndex;
	int options = 0;
   Oid relid = InvalidOid;
   Oid tsroid = InvalidOid;
	char *tsrname;
	char *tsrhandler;
	bool		found = false;
	List	   *indexlist;
	ListCell   *lc;
	Datum		values[Natts_pg_toastrel];
	bool		nulls[Natts_pg_toastrel];
	List *namelist;
	ScanKeyData key[2];
	SysScanDesc scan;
	HeapTuple	tup;
	uint32      total_entries = 0;
	int keys = 0;

	/* Must be superuser */
	if (!superuser())
		ereport(ERROR,
			(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
			 	errmsg("permission denied to create toaster \"%s\"",
					tsrname),
			errhint("Must be superuser to create a toaster.")));

	if (PG_ARGISNULL(0))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("Toaster name cannot be null")));
	if (PG_ARGISNULL(1))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("Toaster handler cannot be null")));

	tsrname = PG_GETARG_CSTRING(0);
	tsrhandler = PG_GETARG_CSTRING(1);

	namelist = stringToQualifiedNameList(tsrhandler, NULL);

	/*
	 * Get the handler function oid, verifying the toaster type while at it.
	 */
	tsroid = lookup_toaster_handler_func(namelist);

/*	tsroid = LookupFuncName(namelist, 0, NULL, false); */

	if(!RegProcedureIsValid(tsroid))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("Toaster handler %s is not valid", tsrhandler)));

	rel = get_rel_from_relname(cstring_to_text(pg_toaster_name), RowExclusiveLock, ACL_INSERT);

	if(!rel)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_TABLE),
				 errmsg("Cannot open pg_toaster table")));

	indexlist = RelationGetIndexList(rel);
	
	Assert(indexlist != NIL);

	num_indexes = list_length(indexlist);

	foreach(lc, indexlist)
	{
		relindx = index_open(lfirst_oid(lc), AccessShareLock);
		idx_oid = RelationGetRelid(relindx);
		index_close(relindx, AccessShareLock);
		found = true;
		break;
	}

	list_free(indexlist);

	if (!found)
	{
		table_close(rel, RowExclusiveLock);
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_FUNCTION),
				 errmsg("no valid index found for toast relation with Oid %u", relid)));
	}

	ScanKeyInit(&key[keys],
			Anum_pg_toaster_tsrname,
			BTEqualStrategyNumber, F_TEXTEQ,
			CStringGetDatum(tsrname));
	keys++;

	scan = systable_beginscan(rel, idx_oid, false,
							  NULL, keys, key);
	keys = 0;
	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		total_entries++;
		tsroid = ((Form_pg_toaster) GETSTRUCT(tup))->oid;
		break;
	}
	systable_endscan(scan);
	table_close(rel, RowExclusiveLock);
	if(OidIsValid(tsroid))
	{
		table_close(rel, RowExclusiveLock);
		return tsroid;
	}

	/*
	 * Insert tuple into pg_toaster.
	 */
	memset(values, 0, sizeof(values));
	memset(nulls, false, sizeof(nulls));

	{
		tsroid = GetNewOidWithIndex(rel, idx_oid,
											 Anum_pg_toaster_oid);

		values[Anum_pg_toaster_oid - 1] = ObjectIdGetDatum(tsroid);
		values[Anum_pg_toaster_tsrname - 1] = CStringGetDatum(tsrname);
		values[Anum_pg_toaster_tsrhandler - 1] = CStringGetDatum(tsrhandler);

		tup = heap_form_tuple(RelationGetDescr(rel), values, nulls);
		CatalogTupleInsert(rel, tup);
		heap_freetuple(tup);
	}

	table_close(rel, RowExclusiveLock);

	return (ObjectIdGetDatum(tsroid));
}

PG_FUNCTION_INFO_V1(set_toaster);

Datum
set_toaster(PG_FUNCTION_ARGS)
{
	Relation	toastrel;
	Relation   *toastidxs;
	int			num_indexes;
	int			validIndex;
	bytea *data;
   char *tsrname;
	char *relname;
	Size data_size;
	int32 offset;
	int options = 0;
   Oid relid;
   Oid tsroid;
   int32 attnum;

	tsrname = (char *) PG_GETARG_CSTRING(0);
	relname = (char *) PG_GETARG_CSTRING(1);
	attnum = PG_GETARG_INT32(2);

	//relid = PG_GETARG_OID(1);
   

	data_size = 0; // VARSIZE(data);
	offset = 0;
	if(data_size == 0)
		PG_RETURN_NULL();

	toastrel = table_open(relid, RowExclusiveLock);
	validIndex = toast_open_indexes(toastrel,
									RowExclusiveLock,
									&toastidxs,
									&num_indexes);
	toast_close_indexes(toastidxs, num_indexes, NoLock);
	table_close(toastrel, NoLock);

	return ObjectIdGetDatum(tsroid);
}

PG_FUNCTION_INFO_V1(drop_toaster);

Datum
drop_toaster(PG_FUNCTION_ARGS)
{
	struct varlena *result;
	struct varlena *attr;
	Relation toastrel;
	char *tsrname = PG_GETARG_CSTRING(0);
	int32 offset = 0;
	int32 length = 0;
   Oid relid = InvalidOid;

	if(strlen(tsrname) == 0)
		PG_RETURN_NULL();
	attr = NULL;

	result = (struct varlena *) palloc(length + VARHDRSZ);
	SET_VARSIZE(result, length + VARHDRSZ);

	if (OidIsValid(relid))
	{
		CHECK_FOR_INTERRUPTS();
		toastrel = table_open(relid, AccessShareLock);
		table_close(toastrel, AccessShareLock);
	}

	PG_RETURN_POINTER(result);
}
