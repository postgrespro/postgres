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
#include "access/attoptions.h"
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
	HeapTuple	tup;
	Datum		values[Natts_pg_toastrel];
	bool		nulls[Natts_pg_toastrel];
	bool		found = false;
	List	   *indexlist;
	ListCell   *lc;
	// int num_indexes = 0;
	Relation relindx;
	Oid relid = InvalidOid;
	Oid idx_oid = InvalidOid;

	ScanKeyData key[2];
	SysScanDesc scan;
	uint32      total_entries = 0;
	int keys = 0;
	Oid tsroid = InvalidOid;

	Relation pg_toaster = get_rel_from_relname(cstring_to_text(PG_TOASTER_NAME), RowExclusiveLock, ACL_INSERT);

	indexlist = RelationGetIndexList(pg_toaster);
	
	Assert(indexlist != NIL);

	// num_indexes = list_length(indexlist);

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
	table_close(pg_toaster, RowExclusiveLock);
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
	Oid			oid;

	pg_toastrel = get_rel_from_relname(cstring_to_text(PG_TOASTREL_NAME), RowExclusiveLock, ACL_INSERT);

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
	bool		found = false;
	List	   *indexlist;
	ListCell   *lc;
	int num_indexes = 0;
	Relation **relindxs;
	Oid relid = InvalidOid;

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
	Relation	rel;
	Relation   relindx;
	Oid			idx_oid;
   Oid relid = InvalidOid;
   Oid tsroid = InvalidOid;
	Oid ex_tsroid = InvalidOid;
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

	elog(NOTICE, "add_toaster 1 enter");

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

	elog(NOTICE, "add_toaster 2 user check");

	/* Must be superuser */
	if (!superuser())
		ereport(ERROR,
			(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
			 	errmsg("permission denied to create toaster \"%s\"",
					tsrname),
			errhint("Must be superuser to create a toaster.")));

	elog(NOTICE, "add_toaster 3 handler");

	namelist = stringToQualifiedNameList(tsrhandler, NULL);

	/*
	 * Get the handler function oid, verifying the toaster type while at it.
	 */

	elog(NOTICE, "add_toaster 4 handler retrieval");

	tsroid = lookup_toaster_handler_func(namelist);

/*	tsroid = LookupFuncName(namelist, 0, NULL, false); */

	if(!RegProcedureIsValid(tsroid))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("Toaster handler %s is not valid", tsrhandler)));

	elog(NOTICE, "add_toaster 5 pg_toaster open");
	rel = get_rel_from_relname(cstring_to_text(PG_TOASTER_NAME), RowExclusiveLock, ACL_INSERT);

	if(!rel)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_TABLE),
				 errmsg("Cannot open pg_toaster table")));

	indexlist = RelationGetIndexList(rel);
	
	Assert(indexlist != NIL);

	//num_indexes = list_length(indexlist);

	foreach(lc, indexlist)
	{
		relindx = index_open(lfirst_oid(lc), AccessShareLock);
		idx_oid = RelationGetRelid(relindx);
		found = true;
		break;
	}

	list_free(indexlist);
elog(NOTICE, "add_toaster 6 index check");
	if (!found)
	{
		index_close(relindx, AccessShareLock);
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
elog(NOTICE, "add_toaster 7 scan");
	scan = systable_beginscan(rel, idx_oid, false,
							  NULL, keys, key);
	keys = 0;
	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		elog(NOTICE, "add_toaster 8 entry check");
		total_entries++;
		ex_tsroid = ((Form_pg_toaster) GETSTRUCT(tup))->oid;
		break;
	}
	systable_endscan(scan);
	if(OidIsValid(ex_tsroid))
	{
		if(ex_tsroid != tsroid)
		elog(NOTICE, "add_toaster 9 found existing");
		index_close(relindx, AccessShareLock);
		table_close(rel, RowExclusiveLock);
		return ObjectIdGetDatum(ex_tsroid);
	}

	/*
	 * Insert tuple into pg_toaster.
	 */
	elog(NOTICE, "add_toaster 10 insert new");
	memset(values, 0, sizeof(values));
	memset(nulls, false, sizeof(nulls));

	{
		NameData tsrnmdata;
		elog(NOTICE, "add_toaster 10-0 name data");
		namestrcpy(&tsrnmdata, tsrname);
		elog(NOTICE, "add_toaster 10-0 get index");
		ex_tsroid = GetNewObjectId();
		//GetNewOidWithIndex(rel, idx_oid,
//											 Anum_pg_toaster_oid);

		values[Anum_pg_toaster_oid - 1] = ObjectIdGetDatum(ex_tsroid);
		values[Anum_pg_toaster_tsrname - 1] = NameGetDatum(&tsrnmdata);
		values[Anum_pg_toaster_tsrhandler - 1] = ObjectIdGetDatum(tsroid); // Datum regprocin(PG_FUNCTION_ARGS) CString Datum(tsrhandler);
		elog(NOTICE, "add_toaster 10-1 heap_form");
		tup = heap_form_tuple(RelationGetDescr(rel), values, nulls);
		elog(NOTICE, "add_toaster 10-2 insert");
		CatalogTupleInsert(rel, tup);
		heap_freetuple(tup);
	}
	elog(NOTICE, "add_toaster 11 close");
	index_close(relindx, AccessShareLock);
	table_close(rel, RowExclusiveLock);

	return (ObjectIdGetDatum(ex_tsroid));
}

PG_FUNCTION_INFO_V1(set_toaster);

Datum
set_toaster(PG_FUNCTION_ARGS)
{
	Relation	rel;
	Relation	tsrrel;
	Relation attrelation;
   char *tsrname;
	char *relname;
	char *attname;
	int len = 0;
   Oid relid = InvalidOid;
   Oid tsroid = InvalidOid;
	Oid tsrhandler = InvalidOid;
	Datum res = (Datum) 0;
	Datum d = (Datum) 0;
	HeapTuple	tuple,
				tsrtup;
	Form_pg_attribute attrtuple;
	AttrNumber	attnum;
	SysScanDesc scan;
	uint32      total_entries = 0;
	// char *str;
	char str[12];
	Oid trelid = InvalidOid;

	if (PG_ARGISNULL(0))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("Toaster name cannot be null")));

	if (PG_ARGISNULL(1))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("Table name cannot be null")));

	if (PG_ARGISNULL(2))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("Attribute name cannot be null")));
	elog(NOTICE, "set_toaster 1 arg check");

	tsrname = (char *) PG_GETARG_CSTRING(0);
	relname = (char *) PG_GETARG_CSTRING(1);
	attname = (char *) PG_GETARG_CSTRING(2);

	if(strlen(tsrname) == 0)
		PG_RETURN_NULL();
	if(strlen(relname) == 0)
		PG_RETURN_NULL();
	if(strlen(attname) == 0)
		PG_RETURN_NULL();
	elog(NOTICE, "set_toaster 2 null check");
	if (!superuser())
		ereport(ERROR,
			(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
			 	errmsg("permission denied to create toaster \"%s\"",
					tsrname),
			errhint("Must be superuser to create a toaster.")));
	elog(NOTICE, "set_toaster 3 user check");
	rel = get_rel_from_relname(cstring_to_text(relname), AccessShareLock, ACL_SELECT);
	relid = RelationGetRelid(rel);
	table_close(rel, AccessShareLock);
	if(!OidIsValid(relid))
	{
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_TABLE),
				 errmsg("Cannot retrieve oid for table %s", relname)));
		return (Datum) 0;
	}
	elog(NOTICE, "set_toaster 4 get relid");
	tsrrel = get_rel_from_relname(cstring_to_text(PG_TOASTER_NAME), AccessShareLock, ACL_SELECT);
	elog(NOTICE, "set_toaster 5 get pg_toaster rel");
	if(!tsrrel)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_TABLE),
				 errmsg("Cannot open pg_toaster table")));

	scan = systable_beginscan(tsrrel, InvalidOid, false,
							  NULL, 0, NULL);

	while (HeapTupleIsValid(tsrtup = systable_getnext(scan)))
	{
		elog(NOTICE, "set_toaster 5-1 scan %u tsr <%s> compare to <%s>", total_entries, NameStr(((Form_pg_toaster) GETSTRUCT(tsrtup))->tsrname),tsrname);
		total_entries++;
		if(strcmp(NameStr(((Form_pg_toaster) GETSTRUCT(tsrtup))->tsrname), tsrname) == 0)
		{
			tsroid = ((Form_pg_toaster) GETSTRUCT(tsrtup))->oid;
			tsrhandler = ((Form_pg_toaster) GETSTRUCT(tsrtup))->tsrhandler;
			elog(NOTICE, "set_toaster 5-2 found %u h %u", tsroid, tsrhandler);
			break;
		}
	}

	systable_endscan(scan);
	table_close(tsrrel, AccessShareLock);
	elog(NOTICE, "set_toaster 6 pg_toaster scan");
	if(!OidIsValid(tsroid))
	{
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_TABLE),
				 errmsg("Cannot find toaster with name %s", tsrname)));

		return (Datum) 0;
	}

	if(!OidIsValid(tsrhandler))
	{
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_TABLE),
				 errmsg("Cannot find handler for toaster with name %s", tsrname)));

		return (Datum) 0;
	}
	elog(NOTICE, "set_toaster 7 opn pg_attribute");
	attrelation = table_open(AttributeRelationId, RowExclusiveLock);
	elog(NOTICE, "set_toaster 8 search attribute");
	tuple = SearchSysCacheAttName(relid, attname);
	elog(NOTICE, "set_toaster 9 syscache");
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_COLUMN),
				 errmsg("column \"%s\" of relation \"%s\" does not exist",
						attname, RelationGetRelationName(rel))));
	attrtuple = (Form_pg_attribute) GETSTRUCT(tuple);

	attnum = attrtuple->attnum;
	if (attnum <= 0)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("cannot alter system column \"%s\"",
						attname)));
	
	ReleaseSysCache(tuple);

	elog(NOTICE, "set_toaster 10 get toater opts ");
	d = attopts_get_toaster_opts(relid, attname, attnum, ATT_TOASTER_NAME);
	if(d != (Datum) 0)
	{
		elog(NOTICE, "set_toaster 10-1 tsr <%s> found", DatumGetCString(d));
	}
	d = attopts_get_toaster_opts(relid, attname, attnum, ATT_TOASTREL_NAME);
	if(d != (Datum) 0)
	{
		elog(NOTICE, "set_toaster 10-2 tsrel <%s> found", DatumGetCString(d));
		table_close(attrelation, RowExclusiveLock);
		return res;
	}
	{
		/* Call tsr->init */
		TsrRoutine *tsr;
			
		elog(NOTICE, "set_toaster 11 datum check");
		d = attopts_get_toaster_opts(relid, attname, attnum, ATT_HANDLER_NAME);
		if(d != (Datum) 0)
		{
			elog(NOTICE, "set_toaster 11-1 handler <%s> found", DatumGetCString(d));
		}

		tsr = GetTsrRoutine(tsrhandler);
		rel = get_rel_from_relname(cstring_to_text(relname), RowExclusiveLock, ACL_INSERT);
		relid = RelationGetRelid(rel);
elog(NOTICE, "set_toaster 12 call tsr init");
		d = tsr->init(rel,
								tsroid,
								(Datum) 0,
								attnum,
								RowExclusiveLock,
								false,
								InvalidOid);
		trelid = DatumGetObjectId(d);
		table_close(rel, RowExclusiveLock);
	}

	table_close(attrelation, RowExclusiveLock);
elog(NOTICE, "set_toaster 13 set opts");
	elog(NOTICE, "set_toaster 13-1 rel %u attname %s", relid, attname);
	if(OidIsValid(trelid))
	{
		len = pg_ltoa(trelid, str);
		elog(NOTICE, "set_toaster 13-1 rel %u attname %s", relid, attname);
		d = attopts_set_toaster_opts(relid, attname, ATT_TOASTREL_NAME, str);
	}

	elog(NOTICE, "set_toaster 13-1 set v1 int %u", tsroid);
	len = pg_ltoa(tsroid, str);
	Assert(len!=0);
	elog(NOTICE, "set_toaster 13-1 set v1 <%s>", str);
	d = attopts_set_toaster_opts(relid, attname, ATT_TOASTER_NAME, str);
	len = pg_ltoa(tsrhandler, str);
	elog(NOTICE, "set_toaster 13-1 set v2 <%s>", str);
	d = attopts_set_toaster_opts(relid, attname, ATT_HANDLER_NAME, str);
	return res;
}
	

PG_FUNCTION_INFO_V1(drop_toaster);

Datum
drop_toaster(PG_FUNCTION_ARGS)
{
	char *tsrname;
	Relation	attrelation;
	Relation	rel;
	Datum o_datum;
	int l_idx = 0;
	Datum res = (Datum) 0;
   Oid tsroid = InvalidOid;
	bool		found = false;
	SysScanDesc scan;
	HeapTuple	tup;
	HeapTuple	tsrtup;
	uint32      total_entries = 0;
	char *s_tsrid;
	int len = 0;

	if (PG_ARGISNULL(0))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("Toaster name cannot be null")));

	tsrname = PG_GETARG_CSTRING(0);

	if(tsrname == NULL || strlen(tsrname) == 0)
		PG_RETURN_NULL();

	/* Must be superuser */
	if (!superuser())
		ereport(ERROR,
			(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
			 	errmsg("permission denied to create toaster \"%s\"",
					tsrname),
			errhint("Must be superuser to create a toaster.")));

	rel = get_rel_from_relname(cstring_to_text(PG_TOASTER_NAME), RowExclusiveLock, ACL_INSERT);

	if(!rel)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_TABLE),
				 errmsg("Cannot open pg_toaster table")));

	scan = systable_beginscan(rel, InvalidOid, false,
							  NULL, 0, NULL);

	while (HeapTupleIsValid(tsrtup = systable_getnext(scan)))
	{
		total_entries++;
		tsroid = ((Form_pg_toaster) GETSTRUCT(tsrtup))->oid;
		break;
	}

	systable_endscan(scan);
	table_close(rel, RowExclusiveLock);

	if(!OidIsValid(tsroid))
	{
		return (Datum) 0;
	}
	s_tsrid = "";
	len = pg_ltoa(tsroid, s_tsrid);
	found = false;

	if(len != 0)
	{
		attrelation = table_open(AttributeRelationId, RowExclusiveLock);
		scan = systable_beginscan(attrelation, InvalidOid, false,
								  NULL, 0, NULL);
		while (HeapTupleIsValid(tup = systable_getnext(scan)))
		{
			bool		isnull;
			ListCell   *cell;
			List	   *o_list;

			o_datum = SysCacheGetAttr(ATTNAME, tup, Anum_pg_attribute_attoptions,
								&isnull);
			o_list = untransformRelOptions(o_datum);
		
			foreach(cell, o_list)
			{
				DefElem    *def = (DefElem *) lfirst(cell);

				char *str;
				l_idx++;
				if (strcmp(def->defname, tsrname) == 0)
				{
					str = defGetString(def);

					if(str && strcmp(s_tsrid, str) == 0)
					{
						found = true;
						break;
					}
				}
			}
			total_entries++;
		}

		systable_endscan(scan);
		heap_freetuple(tup);
		table_close(attrelation, RowExclusiveLock);
	}

	if(!found)
	{
		CatalogTupleDelete(rel, &tsrtup->t_self);
	}
	table_close(rel, RowExclusiveLock);

	return res;
}

PG_FUNCTION_INFO_V1(get_toaster);

Datum get_toaster(PG_FUNCTION_ARGS)
{
	Datum d = (Datum) 0;
	return d;
}

PG_FUNCTION_INFO_V1(list_toasters);

Datum list_toasters(PG_FUNCTION_ARGS)
{
	Datum d = (Datum) 0;
	return d;
}

PG_FUNCTION_INFO_V1(list_toastrels);

Datum list_toastrels(PG_FUNCTION_ARGS)
{
	Datum d = (Datum) 0;
	return d;
}
