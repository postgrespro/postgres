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

	/* Must be superuser */
	if (!superuser())
		ereport(ERROR,
			(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
			 	errmsg("permission denied to create toaster \"%s\"",
					tsrname),
			errhint("Must be superuser to create a toaster.")));

	namelist = stringToQualifiedNameList(tsrhandler, NULL);

	/*
	 * Get the handler function oid, verifying the toaster type while at it.
	 */

	tsroid = lookup_toaster_handler_func(namelist);

	if(!RegProcedureIsValid(tsroid))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("Toaster handler %s is not valid", tsrhandler)));

	rel = get_rel_from_relname(cstring_to_text(PG_TOASTER_NAME), RowExclusiveLock, ACL_INSERT);

	if(!rel)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_TABLE),
				 errmsg("Cannot open pg_toaster table")));

	indexlist = RelationGetIndexList(rel);
	
	Assert(indexlist != NIL);

	foreach(lc, indexlist)
	{
		idx_oid = lfirst_oid(lc);
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
	else
	{
		relindx = index_open(idx_oid, AccessShareLock);
		idx_oid = RelationGetRelid(relindx);
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
		ex_tsroid = ((Form_pg_toaster) GETSTRUCT(tup))->oid;
		break;
	}
	systable_endscan(scan);
	if(OidIsValid(ex_tsroid))
	{
		if(ex_tsroid != tsroid && relindx)
			index_close(relindx, AccessShareLock);

		table_close(rel, RowExclusiveLock);
		return ObjectIdGetDatum(ex_tsroid);
	}

	/*
	 * Insert tuple into pg_toaster.
	 */
	memset(values, 0, sizeof(values));
	memset(nulls, false, sizeof(nulls));

	{
		NameData tsrnmdata;
		namestrcpy(&tsrnmdata, tsrname);
		ex_tsroid = GetNewObjectId();

		values[Anum_pg_toaster_oid - 1] = ObjectIdGetDatum(ex_tsroid);
		values[Anum_pg_toaster_tsrname - 1] = NameGetDatum(&tsrnmdata);
		values[Anum_pg_toaster_tsrhandler - 1] = ObjectIdGetDatum(tsroid); // Datum regprocin(PG_FUNCTION_ARGS) CString Datum(tsrhandler);
		tup = heap_form_tuple(RelationGetDescr(rel), values, nulls);
		CatalogTupleInsert(rel, tup);
		heap_freetuple(tup);
	}

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
	char str[12];
	char nstr[12];
	Oid trelid = InvalidOid;
	int ntoasters;
	ToastAttributes tattrs;


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

	tsrname = (char *) PG_GETARG_CSTRING(0);
	relname = (char *) PG_GETARG_CSTRING(1);
	attname = (char *) PG_GETARG_CSTRING(2);

	if(strlen(tsrname) == 0)
		PG_RETURN_NULL();
	if(strlen(relname) == 0)
		PG_RETURN_NULL();
	if(strlen(attname) == 0)
		PG_RETURN_NULL();

	if (!superuser())
		ereport(ERROR,
			(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
			 	errmsg("permission denied to create toaster \"%s\"",
					tsrname),
			errhint("Must be superuser to create a toaster.")));

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

	tsrrel = get_rel_from_relname(cstring_to_text(PG_TOASTER_NAME), AccessShareLock, ACL_SELECT);
	if(!tsrrel)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_TABLE),
				 errmsg("Cannot open pg_toaster table")));

	scan = systable_beginscan(tsrrel, InvalidOid, false,
							  NULL, 0, NULL);

	while (HeapTupleIsValid(tsrtup = systable_getnext(scan)))
	{
		total_entries++;
		if(strcmp(NameStr(((Form_pg_toaster) GETSTRUCT(tsrtup))->tsrname), tsrname) == 0)
		{
			tsroid = ((Form_pg_toaster) GETSTRUCT(tsrtup))->oid;
			tsrhandler = ((Form_pg_toaster) GETSTRUCT(tsrtup))->tsrhandler;
			break;
		}
	}

	systable_endscan(scan);
	table_close(tsrrel, AccessShareLock);
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

	attrelation = table_open(AttributeRelationId, RowExclusiveLock);
	tuple = SearchSysCacheAttName(relid, attname);

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

	tattrs = palloc(sizeof(ToastAttributesData));
	tattrs->attnum = -1;
	tattrs->ntoasters = 0;
	tattrs->toaster = NULL;
	tattrs->toasteroid = InvalidOid;
	tattrs->toasthandleroid = InvalidOid;
	tattrs->toastreloid = InvalidOid;

	d = attopts_get_toaster_opts(relid, attname, attnum, ATT_NTOASTERS_NAME);
	if(d == (Datum) 0)
		ntoasters = 0;
	else
		ntoasters = atoi(DatumGetCString(d));

	len = pg_ltoa((ntoasters+1), str);
	tattrs->ntoasters = ntoasters;

	for(int i = 1; i <= ntoasters; i++)
	{
		len = pg_ltoa(i, str);

		d = get_complex_att_opt(RelationGetRelid(rel), ATT_HANDLER_NAME, str, len, attnum);
		if(d != (Datum) 0)
		{
			if(strcmp(DatumGetCString(d), str))
			{
				tattrs->toasthandleroid = atoi(DatumGetCString(d));

				d = get_complex_att_opt(RelationGetRelid(rel), ATT_TOASTREL_NAME, str, len, attnum);
				if(d == (Datum) 0)
				{
					trelid = InvalidOid;
				}
				else
				{
					trelid = atoi(DatumGetCString(d));
					tattrs->toastreloid = trelid;
					break;
				}
			}
		}
	}
	
	res = ObjectIdGetDatum(tsroid);

	if(!OidIsValid(trelid))
	{
		TsrRoutine *tsr;
		tsr = GetTsrRoutine(tsrhandler);
		rel = get_rel_from_relname(cstring_to_text(relname), RowExclusiveLock, ACL_INSERT);
		relid = RelationGetRelid(rel);
		tattrs->toaster = tsr;
		
		d = tsr->init(rel,
								tsroid,
								(Datum) 0,
								attnum,
								RowExclusiveLock,
								false,
								InvalidOid,
								tattrs);
		trelid = DatumGetObjectId(d);
		table_close(rel, RowExclusiveLock);
	}
	pfree(tattrs);
	table_close(attrelation, RowExclusiveLock);
	ntoasters++;

	/* Set toaster variables - oid, toast relation id, handler for fast access */
	len = 0;
	len = pg_ltoa((ntoasters), nstr);

	if(OidIsValid(trelid))
	{
		len = pg_ltoa(trelid, str);
		d = set_complex_att_opt(relid, ATT_TOASTREL_NAME, nstr, str, attname, 0);
	}

	len = pg_ltoa(tsroid, str);
	d = set_complex_att_opt(relid, ATT_TOASTER_NAME, nstr, str, attname, 0);

	len = pg_ltoa(tsrhandler, str);
	d = set_complex_att_opt(relid, ATT_HANDLER_NAME, nstr, str, attname, 0);

	d = attopts_set_toaster_opts(relid, attname, ATT_NTOASTERS_NAME, nstr, -1);

	return res;
}

PG_FUNCTION_INFO_V1(reset_toaster);

Datum
reset_toaster(PG_FUNCTION_ARGS)
{
	Relation	rel;
	Relation	attrelation;
	char *relname;
	char *attname;
   Oid relid = InvalidOid;
	Datum res = (Datum) 0;
	Datum d = (Datum) 0;
	HeapTuple	tuple;
	Form_pg_attribute attrtuple;
	AttrNumber	attnum;
	char str[12];
	char nstr[12];
	Oid trelid = InvalidOid;
	int ntoasters;
	int len;

	if (PG_ARGISNULL(0))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("Table name cannot be null")));

	if (PG_ARGISNULL(1))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("Attribute name cannot be null")));

	relname = (char *) PG_GETARG_CSTRING(0);
	attname = (char *) PG_GETARG_CSTRING(1);

	if(strlen(relname) == 0)
		PG_RETURN_NULL();
	if(strlen(attname) == 0)
		PG_RETURN_NULL();

	if (!superuser())
		ereport(ERROR,
			(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
			 	errmsg("permission denied to reset toaster for table \"%s\"",
					relname),
			errhint("Must be superuser to reset a toaster.")));

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

	attrelation = table_open(AttributeRelationId, AccessShareLock);
	tuple = SearchSysCacheAttName(relid, attname);

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
	table_close(attrelation, AccessShareLock);

	d = attopts_get_toaster_opts(relid, attname, attnum, ATT_NTOASTERS_NAME);
	if(d == (Datum) 0)
		return (Datum) 0;
	else
		ntoasters = atoi(DatumGetCString(d));

	len = pg_ltoa((ntoasters+1), str);

	ntoasters++;

	/* Set toaster variables - oid, toast relation id, handler for fast access */
	len = pg_ltoa((ntoasters), nstr);
	if(len <= 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("Number of toasters for attribute \"%s\" of relation \"%s\" is not valid",
						attname, RelationGetRelationName(rel))));

	if(OidIsValid(trelid))
	{
		len = pg_ltoa(rel->rd_rel->reltoastrelid, str);
		d = set_complex_att_opt(relid, ATT_TOASTREL_NAME, nstr, str, attname, 0);
	}

	len = pg_ltoa(InvalidOid, str);
	d = set_complex_att_opt(relid, ATT_TOASTER_NAME, nstr, str, attname, 0);

	len = pg_ltoa(InvalidOid, str);
	d = set_complex_att_opt(relid, ATT_HANDLER_NAME, nstr, str, attname, 0);

	d = attopts_set_toaster_opts(relid, attname, ATT_NTOASTERS_NAME, nstr, -1);

//	attopts_clear_toaster_opts(relid, attname, ATT_NTOASTERS_NAME);
	res = ObjectIdGetDatum(InvalidOid);
	return res;
}

PG_FUNCTION_INFO_V1(get_toaster);

Datum get_toaster(PG_FUNCTION_ARGS)
{
	Relation	rel;
	Relation	tsrrel;
	char *relname;
	char *attname;
   Oid relid = InvalidOid;
	Datum res = (Datum) 0;
	SysScanDesc scan;
	uint32 total_entries = 0;
	Datum d = (Datum) 0;
	Relation attrelation;
	int len = 0;
   Oid tsroid = InvalidOid;
	HeapTuple	tuple,
				tsrtup;
	Form_pg_attribute attrtuple;
	AttrNumber	attnum;
	char str[12];
	int ntoasters;
	char *tsrname = "";

	if (PG_ARGISNULL(0))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("Table name cannot be null")));

	if (PG_ARGISNULL(1))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("Attribute name cannot be null")));

	relname = (char *) PG_GETARG_CSTRING(0);
	attname = (char *) PG_GETARG_CSTRING(1);

	if(strlen(relname) == 0)
		PG_RETURN_NULL();
	if(strlen(attname) == 0)
		PG_RETURN_NULL();

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

	attrelation = table_open(AttributeRelationId, AccessShareLock);
	tuple = SearchSysCacheAttName(relid, attname);

	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_COLUMN),
				 errmsg("column \"%s\" of relation \"%s\" does not exist",
						attname, RelationGetRelationName(rel))));
	attrtuple = (Form_pg_attribute) GETSTRUCT(tuple);

	attnum = attrtuple->attnum;
	ReleaseSysCache(tuple);
	table_close(attrelation, AccessShareLock);

	if (attnum <= 0)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("cannot alter system column \"%s\"",
						attname)));

	d = attopts_get_toaster_opts(relid, attname, attnum, ATT_NTOASTERS_NAME);
	if(d == (Datum) 0)
		ntoasters = 0;
	else
		ntoasters = atoi(DatumGetCString(d));

	len = pg_ltoa((ntoasters+1), str);

	for(int i = 1; i <= ntoasters; i++)
	{
		len = pg_ltoa(i, str);

		d = get_complex_att_opt(RelationGetRelid(rel), ATT_TOASTER_NAME, str, len, attnum);
		if(d != (Datum) 0)
			tsroid = atoi(DatumGetCString(d));
	}

	tsrrel = get_rel_from_relname(cstring_to_text(PG_TOASTER_NAME), AccessShareLock, ACL_SELECT);
	if(!tsrrel)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_TABLE),
				 errmsg("Cannot open pg_toaster table")));

	scan = systable_beginscan(tsrrel, InvalidOid, false,
							  NULL, 0, NULL);

	while (HeapTupleIsValid(tsrtup = systable_getnext(scan)))
	{
		total_entries++;
		if((((Form_pg_toaster) GETSTRUCT(tsrtup))->oid) == tsroid)
		{
			tsrname = (NameStr(((Form_pg_toaster) GETSTRUCT(tsrtup))->tsrname));
			break;
		}
	}

	systable_endscan(scan);
	table_close(tsrrel, AccessShareLock);
	elog(NOTICE,"%s", tsrname);
	res = ObjectIdGetDatum(tsroid);
	// res = PointerGetDatum(cstring_to_text_with_len(tsrname, strlen(tsrname)));

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
	HeapTuple	tup = NULL;
	HeapTuple	tsrtup;
	uint32      total_entries = 0;
	char s_tsrid[12];
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
		if(strcmp(NameStr(((Form_pg_toaster) GETSTRUCT(tsrtup))->tsrname), tsrname) == 0)
		{
			tsroid = ((Form_pg_toaster) GETSTRUCT(tsrtup))->oid;
			break;
		}
	}

	systable_endscan(scan);
	table_close(rel, RowExclusiveLock);

	if(!OidIsValid(tsroid))
	{
		return (Datum) 0;
	}

	len = pg_ltoa(tsroid, s_tsrid);
	found = false;

	if(len != 0)
	{
		attrelation = table_open(AttributeRelationId, RowExclusiveLock);
		scan = systable_beginscan(attrelation, InvalidOid, false,
								  NULL, 0, NULL);
		elog(NOTICE, "6");
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
				str = defGetString(def);

				if(str && strcmp(s_tsrid, str) == 0)
				{
					found = true;
					break;
				}
			}
			total_entries++;
		}
		systable_endscan(scan);
		table_close(attrelation, RowExclusiveLock);
	}

	if(!found)
	{
		rel = get_rel_from_relname(cstring_to_text(PG_TOASTER_NAME), RowExclusiveLock, ACL_INSERT);

		scan = systable_beginscan(rel, InvalidOid, false,
							  NULL, 0, NULL);
		tsroid = InvalidOid;
		while (HeapTupleIsValid(tsrtup = systable_getnext(scan)))
		{
			total_entries++;
			if(strcmp(NameStr(((Form_pg_toaster) GETSTRUCT(tsrtup))->tsrname), tsrname) == 0)
			{
				tsroid = ((Form_pg_toaster) GETSTRUCT(tsrtup))->oid;
				res = ObjectIdGetDatum(tsroid);
				break;
			}
		}
		
		if( OidIsValid(tsroid))
			CatalogTupleDelete(rel, &tsrtup->t_self);

		systable_endscan(scan);
		table_close(rel, RowExclusiveLock);
	}

	return res;
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
	Relation	rel;
	Relation attrelation;
	char *relname;
	char *attname;
	int len = 0;
   Oid relid = InvalidOid;
	Datum res = (Datum) 0;
	Datum d = (Datum) 0;
	HeapTuple	tuple;
	Form_pg_attribute attrtuple;
	AttrNumber	attnum;
	char str[12];
	int ntoasters;
	char *tsrlist = NULL;
	int tlen = 0;

	if (PG_ARGISNULL(0))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("Table name cannot be null")));

	if (PG_ARGISNULL(1))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("Attribute name cannot be null")));

	relname = (char *) PG_GETARG_CSTRING(0);
	attname = (char *) PG_GETARG_CSTRING(1);

	if(strlen(relname) == 0)
		PG_RETURN_NULL();
	if(strlen(attname) == 0)
		PG_RETURN_NULL();

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

	attrelation = table_open(AttributeRelationId, RowExclusiveLock);
	tuple = SearchSysCacheAttName(relid, attname);

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

	if(OidIsValid(rel->rd_rel->reltoastrelid))
	{
		len = pg_ltoa(rel->rd_rel->reltoastrelid, str);
		tlen += len;
	}

	d = attopts_get_toaster_opts(relid, attname, attnum, ATT_NTOASTERS_NAME);
	if(d == (Datum) 0)
		ntoasters = 0;
	else
		ntoasters = atoi(DatumGetCString(d));

	len = pg_ltoa((ntoasters+1), str);

	for(int i = 1; i <= ntoasters; i++)
	{
		len = pg_ltoa(i, str);

		d = get_complex_att_opt(RelationGetRelid(rel), ATT_HANDLER_NAME, str, len, attnum);
		if(d != (Datum) 0)
		{
			if(strcmp(DatumGetCString(d), str))
			{
				d = get_complex_att_opt(RelationGetRelid(rel), ATT_TOASTREL_NAME, str, len, attnum);
				if(d != (Datum) 0)
				{
					if(OidIsValid(DatumGetObjectId(d)))
					{
						len = pg_ltoa(DatumGetObjectId(d) , str);
						elog(NOTICE,"%s", str);
						if(tlen > 0) tlen+=1;
						tlen += len;
					}
				}
			}
		}
	}

	tsrlist = palloc0(tlen+1);

	if(OidIsValid(rel->rd_rel->reltoastrelid))
	{
		len = pg_ltoa(rel->rd_rel->reltoastrelid, str);
		strcat(tsrlist, str);
		tlen = len;
	}
		else tlen = 0;

	len = pg_ltoa((ntoasters+1), str);

	for(int i = 1; i <= ntoasters; i++)
	{
		len = pg_ltoa(i, str);

		d = get_complex_att_opt(RelationGetRelid(rel), ATT_HANDLER_NAME, str, len, attnum);
		if(d != (Datum) 0)
		{
			if(strcmp(DatumGetCString(d), str))
			{
				d = get_complex_att_opt(RelationGetRelid(rel), ATT_TOASTREL_NAME, str, len, attnum);
				if(d != (Datum) 0)
				{
					if(OidIsValid(DatumGetObjectId(d)))
					{
						len = pg_ltoa(DatumGetObjectId(d) , str);
						if(tlen > 0)
							strcat(tsrlist, ",");
						strcat(tsrlist, str);
					}
				}
			}
		}
	}

	table_close(attrelation, RowExclusiveLock);
	if(tsrlist != NULL) 
	{
		strcat(tsrlist, "\0");
		elog(NOTICE,"%s", tsrlist);
		res = PointerGetDatum(cstring_to_text(tsrlist));
	}
	return res;
}
