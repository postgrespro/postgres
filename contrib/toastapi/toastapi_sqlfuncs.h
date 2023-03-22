#ifndef TOASTAPISQL_H
#define TOASTAPISQL_H

#include "postgres.h"
#include "fmgr.h"

extern Datum add_toaster(PG_FUNCTION_ARGS);

extern Datum set_toaster(PG_FUNCTION_ARGS);

extern Datum drop_toaster(PG_FUNCTION_ARGS);

extern Datum get_toaster(PG_FUNCTION_ARGS);

extern Datum list_toasters(PG_FUNCTION_ARGS);

extern Datum list_toastrels(PG_FUNCTION_ARGS);

#endif
