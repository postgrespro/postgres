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
 *		the genbki.pl script reads this file and generates .bki
 *		information from the DATA() statements.
 *
 *		XXX do NOT break up DATA() statements into multiple lines!
 *			the scripts are not as smart as you might think...
 *
 *-------------------------------------------------------------------------
 */
#ifndef PG_TS_CONFIG_MAP_H
#define PG_TS_CONFIG_MAP_H

#include "catalog/genbki.h"
#include "utils/jsonb.h"

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

CATALOG(pg_ts_config_map,3603) BKI_WITHOUT_OIDS
{
	Oid			mapcfg;			/* OID of configuration owning this entry */
	int32		maptokentype;	/* token type from parser */
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

/* ----------------
 *		initial contents of pg_ts_config_map
 * ----------------
 */

DATA(insert ( 3748	1	"[3765]" ));
DATA(insert ( 3748	2	"[3765]" ));
DATA(insert ( 3748	3	"[3765]" ));
DATA(insert ( 3748	4	"[3765]" ));
DATA(insert ( 3748	5	"[3765]" ));
DATA(insert ( 3748	6	"[3765]" ));
DATA(insert ( 3748	7	"[3765]" ));
DATA(insert ( 3748	8	"[3765]" ));
DATA(insert ( 3748	9	"[3765]" ));
DATA(insert ( 3748	10	"[3765]" ));
DATA(insert ( 3748	11	"[3765]" ));
DATA(insert ( 3748	15	"[3765]" ));
DATA(insert ( 3748	16	"[3765]" ));
DATA(insert ( 3748	17	"[3765]" ));
DATA(insert ( 3748	18	"[3765]" ));
DATA(insert ( 3748	19	"[3765]" ));
DATA(insert ( 3748	20	"[3765]" ));
DATA(insert ( 3748	21	"[3765]" ));
DATA(insert ( 3748	22	"[3765]" ));

#endif							/* PG_TS_CONFIG_MAP_H */
