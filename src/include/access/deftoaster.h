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
#include "access/detoast.h"
#include "access/genam.h"
#include "access/heapam.h"
#include "access/heaptoast.h"
#include "access/toast_helper.h"
#include "access/toast_internals.h"
#include "utils/fmgroids.h"
#include "access/toasterapi.h"

Datum genericDetoast(Relation toast_rel,
								Datum toast_ptr,
								int offset, int length);

Datum genericToast(Relation toast_rel,
								Datum newvalue, Datum oldvalue,
								int max_inline_size);

Datum genericDeleteToast(Relation rel, Datum toast_ptr);

void *
genericGetVtable(Datum toast_ptr);

bool
genericToasterValidate(Oid toasteroid);


/*
Datum
generic_toast_save_datum(Relation rel, Datum value,
				 struct varlena *oldexternal, int options);
*/