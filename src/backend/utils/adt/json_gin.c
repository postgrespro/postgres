/*
 * json_gin.c
 *
 * Portions Copyright (c) 2016, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/utils/adt/json_gin.c
 *
 */

#define gin_compare_jsonb				gin_compare_json
#define gin_extract_jsonb				gin_extract_json
#define gin_extract_jsonb_query			gin_extract_json_query
#define gin_consistent_jsonb			gin_consistent_json
#define gin_triconsistent_jsonb			gin_triconsistent_json
#define gin_extract_jsonb_path			gin_extract_json_path
#define gin_extract_jsonb_query_path	gin_extract_json_query_path
#define gin_consistent_jsonb_path		gin_consistent_json_path
#define gin_triconsistent_jsonb_path	gin_triconsistent_json_path

#define JsonxContainerOps				(&jsontContainerOps)
#define JsonxGetUniquified(json)		(json)
#define JsonxPGetDatum(json)			JsontGetDatum(json)

#include "utils/json_generic.h"

#include "jsonb_gin.c"
