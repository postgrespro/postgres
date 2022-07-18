#include "postgres.h"
#include "plpython.h"
#include "utils/jsonb.h"
#include "plpy_typeio.h"

/* Python wrapper for jsonb container */
typedef struct PLyJsonb
{
	PyObject_HEAD
	JsonbContainer *data;
	size_t		len;
	PyObject   *cache;
	int			ncached;
	bool		fully_cached;
	int			replaced_index;
	PyObject   *replaced_value;
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

extern PyObject *PLyJsonb_FromJsonbContainer(JsonbContainer *jsonb);
extern JsonbValue *PLyJsonb_ToJsonbValue(PyObject *obj, JsonbValue *jbv, bool copy);
extern JsonbValue *PLyObject_ToJsonbValue(PyObject *obj, JsonbParseState **jsonb_state, bool is_elem);

extern void PLyString_ToJsonbValue(PyObject *obj, JsonbValue *jbvElem);
extern void PLyKey_ToJsonbValue(PyObject *key, JsonbValue *jbv);
extern PyObject *PLyObject_FromJsonbContainer(JsonbContainer *jsonb);
extern PyObject *PLyObject_FromJsonbValue(JsonbValue *jsonbValue);

/* for PLyObject_AsString in plpy_typeio.c */
typedef char *(*PLyObject_AsString_t) (PyObject *plrv);
extern PLyObject_AsString_t PLyObject_AsString_p;

typedef void (*PLy_elog_impl_t) (int elevel, const char *fmt,...);
extern PLy_elog_impl_t PLy_elog_impl_p;

#if PY_MAJOR_VERSION >= 3
typedef PyObject *(*PLyUnicode_FromStringAndSize_t)
			(const char *s, Py_ssize_t size);
extern PLyUnicode_FromStringAndSize_t PLyUnicode_FromStringAndSize_p;
#endif

typedef MemoryContext (*PLy_get_global_memory_context_t) (void);
extern PLy_get_global_memory_context_t PLy_get_global_memory_context_p;

/* for PLyObject_AsString in plpy_typeio.c */
typedef char *(*PLyObject_AsString_t) (PyObject *plrv);
extern PLyObject_AsString_t PLyObject_AsString_p;
