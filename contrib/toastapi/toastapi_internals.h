#ifndef TOASTAPIINT_H
#define TOASTAPIINT_H

#include "postgres.h"
#include "access/relation.h"
#include "utils/acl.h"

extern Relation
get_rel_from_relname(text *relname_text, LOCKMODE lockmode, AclMode aclmode);

typedef struct ToastAttrContext
{
	Relation	rel;
	Relation	attrel;
	int			attrel_lockmode;
	AttrNumber	attnum;
	HeapTuple	atttup;
	Datum		attoptions;
} ToastAttrContext;

extern void toaster_attopts_init(ToastAttrContext *cxt, Relation rel,
								 const char *attname, bool for_update, Oid toasterid);
extern char *toaster_attopts_get(ToastAttrContext *cxt, char *optname);
extern void toaster_attopts_clear(ToastAttrContext *cxt, char *optname);
extern void toaster_attopts_set(ToastAttrContext *cxt, char *optname, char *optval, int order);
extern void toaster_attopts_update(ToastAttrContext *cxt);
extern void toaster_attopts_free(ToastAttrContext *cxt);

extern char *attopts_get_toaster_opts(Relation rel, int attnum, char *optname);

extern Oid lookup_toaster_handler_func(List *handler_name);

extern Oid get_toaster_by_name(Relation pg_toaster_rel, const char *tsrname, Oid *tsrhandler);
extern char *get_toaster_name(Oid tsroid);

#endif							/* TOASTAPIINT_H */
