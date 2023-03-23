#ifndef TOASTAPIINT_H
#define TOASTAPIINT_H

#include "postgres.h"
#include "access/relation.h"
#include "utils/acl.h"

extern Relation
get_rel_from_relname(text *relname_text, LOCKMODE lockmode, AclMode aclmode);

extern Datum attopts_get_toaster_opts(Oid relOid, int attnum, char *optname);
extern Datum attopts_set_toaster_opts(Oid relOid, char *attname, char *optname, char *optval, int order);
extern Datum attopts_clear_toaster_opts(Oid relOid, char *attname, char *optname);

extern Oid lookup_toaster_handler_func(List *handler_name);

extern Oid get_toaster_by_name(Relation pg_toaster_rel, const char *tsrname, Oid *tsrhandler);
extern char *get_toaster_name(Oid tsroid);

#endif							/* TOASTAPIINT_H */
