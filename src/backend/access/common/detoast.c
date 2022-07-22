/*-------------------------------------------------------------------------
 *
 * detoast.c
 *	  Retrieve compressed or external variable size attributes.
 *
 * Copyright (c) 2000-2022, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/access/common/detoast.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/detoast.h"
#include "access/table.h"
#include "access/tableam.h"
#include "access/toast_internals.h"
#include "common/int.h"
#include "common/pg_lzcompress.h"
#include "utils/expandeddatum.h"
#include "utils/rel.h"
#include "access/toasterapi.h"
/*
static struct varlena *toast_fetch_datum(struct varlena *attr);
static struct varlena *toast_fetch_datum_slice(struct varlena *attr,
											   int32 sliceoffset,
											   int32 slicelength);*/
/*
static struct varlena *toast_decompress_datum(struct varlena *attr);
static struct varlena *toast_decompress_datum_slice(struct varlena *attr, int32 slicelength);
*/

