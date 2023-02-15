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
	Relation *relindxs;
	Oid relid = InvalidOid;

	relid = RelationGetRelid(rel);

	indexlist = RelationGetIndexList(rel);
	
	Assert(indexlist != NIL);

	num_indexes = list_length(indexlist);

	relindxs = (Relation *) palloc(num_indexes * sizeof(Relation));
	foreach(lc, indexlist)
		relindxs[i++] = index_open(lfirst_oid(lc), lock);

	for (i = 0; i < num_indexes; i++)
	{
		Relation	toastidx = relindxs[i];

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
	char *tmp;


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

	d = attopts_get_toaster_opts(relid, attname, attnum, ATT_NTOASTERS_NAME);
	if(d == (Datum) 0)
	{
		ntoasters = 0;
	}
	else
	{
		ntoasters = atoi(DatumGetCString(d));
	}

	len = pg_ltoa((ntoasters+1), str);
//	tmp = palloc(strlen(ATT_HANDLER_NAME) + len + 1);

	for(int i = 1; i <= ntoasters; i++)
	{
		int tlen = 0;
		char tind[12];
		tlen = pg_ltoa(i, tind);
/*		
		memcpy(tmp, ATT_TOASTER_NAME, strlen(ATT_TOASTER_NAME));
		memcpy(tmp+strlen(ATT_TOASTER_NAME), tind, tlen);
		tmp[strlen(ATT_TOASTER_NAME) + tlen] = '\0';
		d = attopts_get_toaster_opts(RelationGetRelid(rel), "", attnum, tmp);
*/
		len = pg_ltoa(i, str);
		tmp = palloc(strlen(ATT_HANDLER_NAME) + tlen + 1);
		memcpy(tmp, ATT_HANDLER_NAME, strlen(ATT_HANDLER_NAME));
		memcpy(tmp+strlen(ATT_HANDLER_NAME), str, tlen);
		tmp[strlen(ATT_HANDLER_NAME) + tlen] = '\0';
		d = attopts_get_toaster_opts(RelationGetRelid(rel), "", attnum, tmp);
		pfree(tmp);

		if(d != (Datum) 0)
		{
			if(strcmp(DatumGetCString(d), str))
			{
				tmp = palloc(strlen(ATT_TOASTREL_NAME) + tlen + 1);
				memcpy(tmp, ATT_TOASTREL_NAME, strlen(ATT_TOASTREL_NAME));
				memcpy(tmp+strlen(ATT_TOASTREL_NAME), tind, tlen);
				tmp[strlen(ATT_TOASTREL_NAME) + tlen] = '\0';
				d = attopts_get_toaster_opts(RelationGetRelid(rel), "", attnum, tmp);
				pfree(tmp);
				if(d == (Datum) 0)
				{
					trelid = InvalidOid;
				}
				else
				{
					trelid = atoi(DatumGetCString(d));
					break;
				}
			}
		}
	}

	if(!OidIsValid(trelid))
	{
		/* Call tsr->init */
		TsrRoutine *tsr;
		tsr = GetTsrRoutine(tsrhandler);
		rel = get_rel_from_relname(cstring_to_text(relname), RowExclusiveLock, ACL_INSERT);
		relid = RelationGetRelid(rel);
		
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
	ntoasters++;

	/* Set toaster variables - oid, toast relation id, handler for fast access */
	len = 0;
	len = pg_ltoa((ntoasters), nstr);

	if(OidIsValid(trelid))
	{
		tmp = palloc(strlen(ATT_TOASTREL_NAME) + len + 1);
		memcpy(tmp, ATT_TOASTREL_NAME, strlen(ATT_TOASTREL_NAME));
		memcpy(tmp+strlen(ATT_TOASTREL_NAME), nstr, len);
		tmp[strlen(ATT_TOASTREL_NAME) + len] = '\0';
		len = pg_ltoa(trelid, str);
		d = attopts_set_toaster_opts(relid, attname, tmp, str, 0);
		pfree(tmp);
	}

	tmp = palloc(strlen(ATT_TOASTER_NAME) + len + 1);
	memcpy(tmp, ATT_TOASTER_NAME, strlen(ATT_TOASTER_NAME));
	memcpy(tmp+strlen(ATT_TOASTER_NAME), nstr, len);
	tmp[strlen(ATT_TOASTER_NAME) + len] = '\0';
	len = pg_ltoa(tsroid, str);
	Assert(len!=0);
	d = attopts_set_toaster_opts(relid, attname, tmp, str, 0);
	pfree(tmp);

	tmp = palloc(strlen(ATT_HANDLER_NAME) + len + 1);
	memcpy(tmp, ATT_HANDLER_NAME, strlen(ATT_HANDLER_NAME));
	memcpy(tmp+strlen(ATT_HANDLER_NAME), nstr, len);
	tmp[strlen(ATT_HANDLER_NAME) + len] = '\0';
	len = pg_ltoa(tsrhandler, str);
	d = attopts_set_toaster_opts(relid, attname, tmp, str, 0);
	pfree(tmp);

	d = attopts_set_toaster_opts(relid, attname, ATT_NTOASTERS_NAME, nstr, -1);

	pfree(tmp);
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
		tsroid = ((Form_pg_toaster) GETSTRUCT(tsrtup))->oid;
		break;
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
/*
				if (strcmp(def->defname, tsrname) == 0)
				{*/
					str = defGetString(def);

					if(str && strcmp(s_tsrid, str) == 0)
					{
						found = true;
						break;
					}
/*				}*/
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
