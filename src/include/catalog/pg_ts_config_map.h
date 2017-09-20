/*-------------------------------------------------------------------------
 *
 * pg_ts_config_map.h
 *	definition of token mappings for configurations of tsearch
 *
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
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

typedef Jsonb jsonb;

CATALOG(pg_ts_config_map,3603) BKI_WITHOUT_OIDS
{
	Oid			mapcfg;			/* OID of configuration owning this entry */
	int32		maptokentype;	/* token type from parser */
	jsonb		mapdicts;		/* dictionary map Jsonb representation */
} FormData_pg_ts_config_map;

typedef FormData_pg_ts_config_map *Form_pg_ts_config_map;

typedef struct TSMapExpression
{
	int			operator;
	Oid			dictionary;
	int			options;
	bool		is_true;
	struct TSMapExpression *left;
	struct TSMapExpression *right;
} TSMapExpression;

typedef struct TSMapCommand
{
	bool		is_expression;
	void	   *ruleList;		/* this is a TSMapRuleList object */
	TSMapExpression *expression;
} TSMapCommand;

typedef struct TSMapCondition
{
	TSMapExpression *expression;
} TSMapCondition;

typedef struct TSMapRule
{
	Oid			dictionary;
	TSMapCondition condition;
	TSMapCommand command;
} TSMapRule;

typedef struct TSMapRuleList
{
	TSMapRule  *data;
	int			count;
} TSMapRuleList;

/* ----------------
 *		compiler constants for pg_ts_config_map
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
#define DICTMAP_OP_OR			1
#define DICTMAP_OP_AND			2
#define DICTMAP_OP_THEN			3
#define DICTMAP_OP_MAPBY		4
#define DICTMAP_OP_UNION		5
#define DICTMAP_OP_EXCEPT		6
#define DICTMAP_OP_INTERSECT	7
#define DICTMAP_OP_NOT			8

/* ----------------
 *		Dictionary map operant options (bit mask)
 * ----------------
 */

#define DICTMAP_OPT_NOT			1
#define DICTMAP_OPT_IS_NULL		2
#define DICTMAP_OPT_IS_STOP		4

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
