#include "postgres.h"
#include "plpython.h"
#include "utils/jsonb.h"

/* Python wrapper for jsonb container */
typedef struct PLyJsonb
{
	PyObject_HEAD
	JsonbContainer *data;
	size_t		len;
} PLyJsonb;

/* Python types based on PLyJsonb structure */
extern PyTypeObject PLyJsonbObject_Type;
extern PyTypeObject PLyJsonbArray_Type;

static inline int
PLyJsonb_Check(PyObject *obj)
{
	return
		Py_TYPE(obj) == &PLyJsonbObject_Type ||
		Py_TYPE(obj) == &PLyJsonbArray_Type;
}

extern PyObject *PLyJsonb_FromJsonbContainer(JsonbContainer *jsonb, size_t len);
extern JsonbValue *PLyJsonb_ToJsonbValue(PyObject *obj, JsonbValue *jbv, bool copy);

extern void PLyString_ToJsonbValue(PyObject *obj, JsonbValue *jbvElem);
extern void PLyKey_ToJsonbValue(PyObject *key, JsonbValue *jbv);
extern PyObject *PLyObject_FromJsonbContainer(JsonbContainer *jsonb);
extern PyObject *PLyObject_FromJsonbValue(JsonbValue *jsonbValue);

typedef MemoryContext (*PLy_get_global_memory_context_t) (void);
extern PLy_get_global_memory_context_t PLy_get_global_memory_context_p;
