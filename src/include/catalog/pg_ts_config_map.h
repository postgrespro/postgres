/*-------------------------------------------------------------------------
 *
 * pg_ts_config_map.h
 *	definition of token mappings for configurations of tsearch
 *
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/catalog/pg_ts_config_map.h
 *
 * NOTES
 *	  The Catalog.pm module reads this file and derives schema
 *	  information.
 *
 *-------------------------------------------------------------------------
 */
#ifndef PG_TS_CONFIG_MAP_H
#define PG_TS_CONFIG_MAP_H

#include "catalog/genbki.h"
#include "utils/jsonb.h"
#include "catalog/pg_ts_config_map_d.h"

/* ----------------
 *		pg_ts_config_map definition.  cpp turns this into
 *		typedef struct FormData_pg_ts_config_map
 * ----------------
 */
#define TSConfigMapRelationId	3603

/*
 * Create a typedef in order to use same type name in
 * generated DB initialization script and C source code
 */
typedef Jsonb jsonb;

CATALOG(pg_ts_config_map,3603,TSConfigMapRelationId) BKI_WITHOUT_OIDS
{
	Oid			mapcfg;			/* OID of configuration owning this entry */
	int32		maptokentype;	/* token type from parser */

	/*
	 * mapdicts is the only one variable-length field so it is safe to use
	 * it directly, without hiding from C interface.
	 */
	jsonb		mapdicts;		/* dictionary map Jsonb representation */
} FormData_pg_ts_config_map;

typedef FormData_pg_ts_config_map *Form_pg_ts_config_map;

/*
 * Element of the mapping expression tree
 */
typedef struct TSMapElement
{
	int			type; /* Type of the element */
	union
	{
		struct TSMapExpression *objectExpression;
		struct TSMapCase *objectCase;
		Oid			objectDictionary;
		void	   *object;
	} value;
	struct TSMapElement *parent; /* Parent in the expression tree */
} TSMapElement;

/*
 * Representation of expression with operator and two operands
 */
typedef struct TSMapExpression
{
	int			operator;
	TSMapElement *left;
	TSMapElement *right;
} TSMapExpression;

/*
 * Representation of CASE structure inside database
 */
typedef struct TSMapCase
{
	TSMapElement *condition;
	TSMapElement *command;
	TSMapElement *elsebranch;
	bool		match;	/* If false, NO MATCH is used */
} TSMapCase;

/* ----------------
 *		Compiler constants for pg_ts_config_map
 * ----------------
 */
#define Natts_pg_ts_config_map				3
#define Anum_pg_ts_config_map_mapcfg		1
#define Anum_pg_ts_config_map_maptokentype	2
#define Anum_pg_ts_config_map_mapdicts		3

/* ----------------
 *		Dictionary map operators
 * ----------------
 */
#define TSMAP_OP_MAP			1
#define TSMAP_OP_UNION			2
#define TSMAP_OP_EXCEPT			3
#define TSMAP_OP_INTERSECT		4
#define TSMAP_OP_COMMA			5

/* ----------------
 *		TSMapElement object types
 * ----------------
 */
#define TSMAP_EXPRESSION	1
#define TSMAP_CASE			2
#define TSMAP_DICTIONARY	3
#define TSMAP_KEEP			4

#endif							/* PG_TS_CONFIG_MAP_H */
