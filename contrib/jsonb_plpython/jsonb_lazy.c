#include "postgres.h"
#include "plpython.h"
#include "jsonb_plpython.h"

#define PLPY_JSONB_MODULE_NAME "plpy_jsonb"
#define PLPY_JSONB_TYPE_NAME_PREFIX PLPY_JSONB_MODULE_NAME "."
#define PLPY_JSONB_TYPE_NAME(type) PLPY_JSONB_TYPE_NAME_PREFIX type

#define PLy_get_global_memory_context (PLy_get_global_memory_context_p)
#define PLyObject_AsString (PLyObject_AsString_p)

static PyObject *
PLyJsonbArray_get_or_transform_item(PLyJsonb *jb, int index, JsonbValue *jbv);

/* Implementation of JsonbArray/JsonbObject type's tp_new(). */
static PyObject *
PLyJsonb_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	return type->tp_alloc(type, 0);
}

/* Implementation of JsonbArray/JsonbObject type's tp_dealloc(). */
static void
PLyJsonb_dealloc(PLyJsonb *self)
{
	Py_DECREF(self->cache);
	PyMem_Free(self->data);
	Py_TYPE(self)->tp_free((PyObject *) self);
}

/* Implementation of JsonbArray/JsonbObject type's tp_repr(). */
static PyObject *
PLyJsonb_repr(PLyJsonb *obj)
{
	char	   *str = JsonbToCString(NULL, obj->data, -1);
	PyObject   *res = PyUnicode_FromStringAndSize(str, strlen(str));

	pfree(str);

	return res;
}

/* Returns borrowed reference. */
static PyObject *
PLyJsonbObject_getkey_cached(PLyJsonb *self, PyObject *key)
{
	return PyDict_GetItem(self->cache, key);
}

static PyObject *
PLyJsonbObject_cache_key(PLyJsonb *self, PyObject *key, PyObject *val)
{
	if (PyDict_SetItem(self->cache, key, val) < 0)
		return NULL;

	self->fully_cached = PyDict_Size(self->cache) >= JsonContainerSize(self->data);

	return val;
}

/* Returns false on error, true otherwise. */
static bool
PLyJsonbObject_getkey(PyObject *obj, PyObject *key, bool throwError,
					  JsonbValue **res)
{
	PLyJsonb   *self = (PLyJsonb *) obj;
	PyObject   *keystr = PyObject_Str(key);
	JsonbValue	kval;
	JsonbValue *retval;
	Py_ssize_t len;

	if (!keystr)
		return false;

	kval.type = jbvString;

#if PY_MAJOR_VERSION >= 3
	kval.val.string.val = (char *) PyUnicode_AsUTF8AndSize(keystr, &len);
	if (!kval.val.string.val)
		return false;
#else
	if (PyString_AsStringAndSize(keystr, &kval.val.string.val, &len) < 0)
		return false;
#endif

	kval.val.string.len = len;

	retval = findJsonbValueFromContainer(self->data, JB_FOBJECT, &kval);

	Py_DECREF(keystr);

	if (!retval && throwError)
	{
		PyErr_Format(PyExc_KeyError, "key '%s' is absent in JsonbObject",
					 kval.val.string.val);
		return false;
	}

	*res = retval;
	return true;
}

static bool
PLyJsonbObject_subscript_cached(PyObject *obj, PyObject *key, bool throwError,
								PyObject **res)
{
	PLyJsonb   *self = (PLyJsonb *) obj;
	PyObject   *val = PLyJsonbObject_getkey_cached(self, key);
	JsonbValue *jbv;

	if (val)
	{
		Py_INCREF(val);
		*res = val;
		return true;
	}

	if (self->fully_cached)
	{
		*res = NULL;
		return true;
	}

	if (!PLyJsonbObject_getkey(obj, key, throwError, &jbv))
		return false;

	if (!jbv)
	{
		*res = NULL;
		return true;
	}

	*res = val = PLyObject_FromJsonbValue(jbv); // PLyJsonb_FromJsonbValue(jbv);

	return PLyJsonbObject_cache_key(self, key, val) != NULL;
}

static PyObject *
PLyJsonbObject_subscript(PyObject *obj, PyObject *key)
{
	PyObject   *val;

	if (!PyString_Check(key))
		return PyErr_Format(PyExc_KeyError,
							"key '%s' is absent in JsonbObject",
							 PLyObject_AsString(key));

	if (!PLyJsonbObject_subscript_cached(obj, key, true, &val))
		return NULL;

	if (!val)
		return PyErr_Format(PyExc_KeyError,
							"key '%s' is absent in JsonbObject",
							 PLyObject_AsString(key));

	return val;
}

/* Implementation of sq_contains() method for JsonbObject */
static int
PLyJsonbObject_contains(PyObject *obj, PyObject *key)
{
	JsonbValue *retval;

	if (!PLyJsonbObject_getkey(obj, key, false, &retval))
		return -1;

	return retval ? 1 : 0;
}

/* Implementation of JsonbObject.get() method */
static PyObject *
PLyJsonbObject_get(PyObject *self, PyObject *args)
{
	PyObject   *val;
	PyObject   *key = NULL;
	PyObject   *default_value = NULL;

	if (!PyArg_ParseTuple(args, "O|O", &key, &default_value))
		return NULL;

	if (!PLyJsonbObject_subscript_cached(self, key, false, &val))
		return NULL;

	if (!val)
		val = default_value ? default_value : Py_None;

	Py_INCREF(val);

	return val;
}

/* JsonbIterator type */
typedef enum
{
	PLPY_JSONB_ITER_ITEMS,
	PLPY_JSONB_ITER_KEYS,
	PLPY_JSONB_ITER_VALUES,
	PLPY_JSONB_ITER_ELEMENTS
} IterType;

/* Structure of JsonbIterator type. */
typedef struct PLyJsonbIter
{
	PyObject_HEAD
	PLyJsonb    *object;
	JsonbIterator *iter;
	IterType	type;
	int			index;
} PLyJsonbIter;

static PyObject *
PLyJsonbIter_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	PLyJsonbIter *iter = (PLyJsonbIter *) type->tp_alloc(type, 0);

	return (PyObject *) iter;
}

static void
PLyJsonbIter_dealloc(PyObject *self)
{
	PLyJsonbIter *iter = (PLyJsonbIter *) self;
	JsonbIterator *jbiter = iter->iter;

	while (jbiter)
	{
		JsonbIterator *parent = jbiter->parent;

		pfree(jbiter);
		jbiter = parent;
	}

	Py_DECREF(iter->object);
	Py_TYPE(self)->tp_free((PyObject *) self);
}

static void
PLyJsonbIter_unexpected_state()
{
	elog(ERROR, "unexpected jsonb iterator state");
}

static PyObject *
PLyJsonb_iterKeyValue(JsonbValue *jbvkey, JsonbValue *jbvval, IterType iterType)
{
	if (iterType == PLPY_JSONB_ITER_KEYS)
	{
		return PLyObject_FromJsonbValue(jbvkey);
	}
	else if (iterType == PLPY_JSONB_ITER_VALUES)
	{
		return PLyObject_FromJsonbValue(jbvval);
	}
	else if (iterType == PLPY_JSONB_ITER_ITEMS)
	{
		PyObject   *key = PLyObject_FromJsonbValue(jbvkey);
		PyObject   *val = PLyObject_FromJsonbValue(jbvval);
		PyObject   *pair;

		Assert(iterType == PLPY_JSONB_ITER_ITEMS);

		if (!key || !val)
		{
			Py_XDECREF(key);
			Py_XDECREF(val);
			return NULL;
		}

		pair = PyTuple_Pack(2, key, val);
		Py_DECREF(key);
		Py_DECREF(val);

		return pair;
	}
	else
		elog(ERROR, "invalid jsonb iterator type");
}

/* Implementation of JsonbIterator type's tp_iternext() */
static PyObject *
PLyJsonbIter_iternext(PyObject *self)
{
	PLyJsonbIter *iter = (PLyJsonbIter *) self;
	PLyJsonb   *jb = iter->object;
	JsonbValue	jbvkey;
	JsonbValue	jbvval;

	if (!iter->iter)
		return NULL;	/* end of iteration */

	switch (JsonbIteratorNext(&iter->iter, &jbvkey, true))
	{
		case WJB_END_OBJECT:
		case WJB_END_ARRAY:
		case WJB_DONE:
			if (iter->type != PLPY_JSONB_ITER_KEYS)
				jb->fully_cached = true;
			return NULL;	/* end of iteration */

		case WJB_KEY:
		{
			PyObject *key = PLyObject_FromJsonbValue(&jbvkey);

			if (JsonbIteratorNext(&iter->iter, &jbvval, true) != WJB_VALUE)
				break;

			if (iter->type == PLPY_JSONB_ITER_KEYS)
			{
				return key;
			}
			else if (iter->type != PLPY_JSONB_ITER_ELEMENTS)
			{
				PyObject   *val = PLyJsonbObject_getkey_cached(jb, key);
				PyObject   *res;

				if (val)
				{
					if (iter->type == PLPY_JSONB_ITER_VALUES)
					{
						Py_INCREF(val);
						res = val;
					}
					else
						res = PyTuple_Pack(2, key, val);
				}
				else
				{
					val = PLyObject_FromJsonbValue(&jbvval);

					if (val)
					{
						if (!PLyJsonbObject_cache_key(jb, key, val))
							res = NULL;
						else if (iter->type == PLPY_JSONB_ITER_VALUES)
							res = val;
						else
						{
							res = PyTuple_Pack(2, key, val);
							Py_DECREF(val);
						}
					}
					else
						res = NULL;
				}

				Py_DECREF(key);

				return res;
			}
		}

		case WJB_ELEM:
			Assert(iter->type == PLPY_JSONB_ITER_ELEMENTS);
			return PLyJsonbArray_get_or_transform_item(jb, iter->index++, &jbvkey);

		default:
			break;
	}

	PLyJsonbIter_unexpected_state();
	return NULL;
}

static PyTypeObject
PLyJsonbIter_Type;

static PyObject *
PLyJsonb_makeIter(PyObject *self, IterType type)
{
	PLyJsonbIter *iter;
	PLyJsonb *obj = (PLyJsonb *) self;

	PyType_Ready(&PLyJsonbIter_Type);

	iter = (PLyJsonbIter *)
		PLyJsonbIter_Type.tp_new(&PLyJsonbIter_Type, NULL, NULL);

	if (!iter)
		return NULL;

	Py_INCREF(obj);
	iter->object = obj;
	iter->type = type;
	iter->iter= NULL;
	iter->index = 0;

	/* Allocate JsonbIteratorContext in the global PL/Python memory context. */
	PG_TRY();
	{
		MemoryContext oldcxt;
		JsonbValue	jbv;

		oldcxt = MemoryContextSwitchTo(PLy_get_global_memory_context());
		iter->iter = JsonbIteratorInit(obj->data);
		MemoryContextSwitchTo(oldcxt);

		if (JsonbIteratorNext(&iter->iter, &jbv, true) !=
			(type == PLPY_JSONB_ITER_ELEMENTS ? WJB_BEGIN_ARRAY : WJB_BEGIN_OBJECT))
			PLyJsonbIter_unexpected_state();
	}
	PG_CATCH();
	{
		Py_DECREF(iter);
		PG_RE_THROW();
	}
	PG_END_TRY();

	return (PyObject *) iter;
}

/* Implementation of JsonbIterator type's tp_iter() */
static PyObject *
PLyJsonbIter_iter(PyObject *self)
{
	PLyJsonbIter *iter = (PLyJsonbIter *) self;

	return PLyJsonb_makeIter((PyObject *) iter->object, iter->type);
}

/* Subroutine for JsonbObject's items(), keys(), and values() methods */
static PyObject *
PLyJsonbObject_list(PyObject *self, int type)
{
	PyObject   *list = PyList_New(0);

	if (!list)
		return NULL;

	PG_TRY();
	{
		PLyJsonb   *obj = (PLyJsonb *) self;
		JsonbIterator *it;
		JsonbIteratorToken tok;
		JsonbValue	jbvkey;
		JsonbValue	jbvval;

		it = JsonbIteratorInit(obj->data);

		while ((tok = JsonbIteratorNext(&it, &jbvkey, true)) != WJB_DONE)
		{
			PyObject   *elem;

			if (tok != WJB_KEY)
				continue;

			if (JsonbIteratorNext(&it, &jbvval, true) != WJB_VALUE)
				elog(ERROR, "unexpected jsonb iterator state");

			elem = PLyJsonb_iterKeyValue(&jbvkey, &jbvval, type);

			if (!elem || PyList_Append(list, elem))
			{
				Py_DECREF(list);
				return NULL;
			}

			Py_DECREF(elem);
		}
	}
	PG_CATCH();
	{
		Py_DECREF(list);
		PG_RE_THROW();
	}
	PG_END_TRY();

	return list;
}

/* Implementation of JsonbObject.items() method */
static PyObject *
PLyJsonbObject_items(PyObject *self, PyObject *args)
{
	return PLyJsonbObject_list(self, PLPY_JSONB_ITER_ITEMS);
}

/* Implementation of JsonbObject.keys() method */
static PyObject *
PLyJsonbObject_keys(PyObject *self, PyObject *args)
{
	return PLyJsonbObject_list(self, PLPY_JSONB_ITER_KEYS);
}

/* Implementation of JsonbObject.values() method */
static PyObject *
PLyJsonbObject_values(PyObject *self, PyObject *args)
{
	return PLyJsonbObject_list(self, PLPY_JSONB_ITER_VALUES);
}

/* Implementation of JsonbObject.iteritems() method */
static PyObject *
PLyJsonbObject_iteritems(PyObject *self, PyObject *args)
{
	PLyJsonb   *arr = (PLyJsonb *) self;

	if (arr->fully_cached)
		return PyObject_CallMethod(arr->cache, "iteritems", NULL);

	return PLyJsonb_makeIter(self, PLPY_JSONB_ITER_ITEMS);
}

/* Implementation of JsonbObject.iterkeys() method */
static PyObject *
PLyJsonbObject_iterkeys(PyObject *self, PyObject *args)
{
	PLyJsonb   *arr = (PLyJsonb *) self;

	if (arr->fully_cached)
		return PyObject_CallMethod(arr->cache, "iterkeys", NULL);

	return PLyJsonb_makeIter(self, PLPY_JSONB_ITER_KEYS);
}

/* Implementation of JsonbObject.itervalues() method */
static PyObject *
PLyJsonbObject_itervalues(PyObject *self, PyObject *args)
{
	PLyJsonb   *arr = (PLyJsonb *) self;

	if (arr->fully_cached)
		return PyObject_CallMethod(arr->cache, "itervalues", NULL);

	return PLyJsonb_makeIter(self, PLPY_JSONB_ITER_VALUES);
}

/* Implementation of JsonbObject type's tp_iter() */
static PyObject *
PLyJsonbObject_iter(PyObject *self)
{
	PLyJsonb   *arr = (PLyJsonb *) self;

	if (arr->fully_cached)
		return PyObject_CallMethod(arr->cache, "iterkeys", NULL);

	return PLyJsonb_makeIter(self, PLPY_JSONB_ITER_KEYS);
}

/* Implementation of sq_length() method. */
static Py_ssize_t
PLyJsonb_length(PyObject *obj)
{
	PLyJsonb *jb = (PLyJsonb *) obj;

	return JsonContainerSize(jb->data);
}

static PyMappingMethods
PLyJsonbObject_MappingMethods =
{
	.mp_length = PLyJsonb_length,
	.mp_subscript = PLyJsonbObject_subscript
};

/* Hack to implement "key in dict" */
static PySequenceMethods
PLyJsonbObject_SequenceMethods =
{
	.sq_contains = PLyJsonbObject_contains
};

/* Implementation of standard Python read-only dict methods for JsonbObject. */
static PyMethodDef
PLyJsonbObject_methods[] =
{
	{ "get",        PLyJsonbObject_get, METH_VARARGS, NULL },
	{ "items",      PLyJsonbObject_items, METH_VARARGS, NULL },
	{ "keys",       PLyJsonbObject_keys, METH_VARARGS, NULL },
	{ "values",     PLyJsonbObject_values, METH_VARARGS, NULL },
	{ "iteritems",  PLyJsonbObject_iteritems, METH_VARARGS, NULL },
	{ "iterkeys",   PLyJsonbObject_iterkeys, METH_VARARGS, NULL },
	{ "itervalues", PLyJsonbObject_itervalues, METH_VARARGS, NULL },
	{ NULL }
};

/* Implementation of JsonbArray sq_length() sequence method */
static Py_ssize_t
PLyJsonbArray_length(PyObject *obj)
{
	PLyJsonb *jb = (PLyJsonb *) obj;

	return JsonContainerSize(jb->data);
}

/* Implementation of sq_item() sequence method for JsonbArray. */
static PyObject *
PLyJsonbArray_item_cached(PLyJsonb *jb, Py_ssize_t index)
{
	PyObject *res = PyList_GET_ITEM(jb->cache, index);

	if (res)
		Py_INCREF(res);

	return res;
}

static PyObject *
PLyJsonbArray_cache_item(PLyJsonb *jb, Py_ssize_t index, PyObject *item)
{
	Py_INCREF(item);
	PyList_SetItem(jb->cache, index, item);

	if (++jb->ncached >= JsonContainerSize(jb->data))
		jb->fully_cached = true;

	return item;
}

static PyObject *
PLyJsonbArray_get_or_transform_item(PLyJsonb *jb, int index, JsonbValue *jbv)
{
	PyObject *res = PLyJsonbArray_item_cached(jb, index);

	if (!res)
	{
		res = PLyObject_FromJsonbValue(jbv);

		if (PyList_GET_SIZE(jb->cache) <= index)
			elog(ERROR, "jsonb iterator returned extra elements");

		PLyJsonbArray_cache_item(jb, index, res);
	}

	return res;
}

static PyObject *
PLyJsonbArray_item(PyObject *obj, Py_ssize_t i)
{
	PLyJsonb   *jb = (PLyJsonb *) obj;
	PyObject   *val;
	JsonbValue *retval;
	int32		size = JsonContainerSize(jb->data);

	if (i < 0)
		i += size;

	if (i < 0 || i >= size)
		retval = NULL;
	else
	{
		val = PLyJsonbArray_item_cached(jb, i);

		if (val)
			return val;

		retval = getIthJsonbValueFromContainer(jb->data, (uint32) i);
	}

	if (!retval)
		return PyErr_Format(PyExc_IndexError, "JsonbArray index out of range");

	val = PLyObject_FromJsonbValue(retval); // PLyJsonb_FromJsonbValue(retval);

	PLyJsonbArray_cache_item(jb, i, val);

	return val;
}

/* Implementation of Sequence protocol for JsonbArray. */
static PySequenceMethods
PLyJsonbArray_SequenceMethods =
{
	.sq_length = PLyJsonbArray_length,
	.sq_item = PLyJsonbArray_item,
	.sq_ass_item = NULL	/* JsonbArray is read-only */
};

/* Compare jsonb to Python list without full transformation to list. */
static int
PLyJsonb_compareToList(JsonbContainer *jbc, PyObject *other)
{
	JsonbIterator *it;
	JsonbIteratorToken r;
	JsonbValue	v;
	int			i = 0;
	int			size = PySequence_Size(other);

	if (!JsonContainerIsArray(jbc) ||
		JsonContainerIsScalar(jbc))
		return -1;	/* non-arrays are lesser than arrays */

	it = JsonbIteratorInit(jbc);

	while ((r = JsonbIteratorNext(&it, &v, true)) != WJB_DONE)
	{
		if (r == WJB_ELEM)
		{
			PyObject   *elem;
			PyObject   *item = NULL;
			int			cmp;

			if (i >= size)
				return 1;

			if (!(elem = PLyObject_FromJsonbValue(&v)) ||
				!(item = PySequence_ITEM(other, i)) ||
				PyObject_Cmp(elem, item, &cmp) < 0)
				cmp = -2;	/* error */
			else if (cmp > 0)
				cmp = 1;
			else if (cmp < 0)
				cmp = -1;

			Py_XDECREF(item);
			Py_XDECREF(elem);

			if (cmp)
				return cmp;

			i++;
		}
	}

	return i < size ? -1 : 0;
}

/* Compare jsonb to Python dict without full transformation into dict. */
static int
PLyJsonb_compareToDict(JsonbContainer *jbc, PyObject *other)
{
	/* We need it volatile, since we use it after longjmp */
	PyObject * volatile items_v = NULL;
	PyObject * volatile differing_key = NULL;
	Py_ssize_t	pcount;
	int			res = 0;

	if (JsonContainerIsScalar(jbc))
		return -1;	/* scalars are lesser than objects */

	if (JsonContainerIsArray(jbc))
		return 1;	/* arrays are greater than objects */

	pcount = PyMapping_Size(other);

	/* Objects are compared first by their size. */
	if (JsonContainerSize(jbc) > pcount)
		return 1;

	if (JsonContainerSize(jbc) < pcount)
		return -1;

	items_v = PyMapping_Items(other);
	if (!items_v)
		return -2;	/* error */

	PG_TRY();
	{
		Py_ssize_t	i;
		PyObject   *items;

		items = (PyObject *) items_v;

		for (i = 0; i < pcount; i++)
		{
			JsonbValue	jbvKey;
			JsonbValue *jbvVal;
			PyObject   *item = PyList_GetItem(items, i);
			PyObject   *key = PyTuple_GetItem(item, 0);
			PyObject   *value = PyTuple_GetItem(item, 1);
			PyObject   *value2;
			int			cmp;

			PLyKey_ToJsonbValue(key, &jbvKey);

			jbvVal = findJsonbValueFromContainer(jbc, JB_FOBJECT, &jbvKey);

			if (!jbvVal)
			{
				/*
				 * Objects have uncommon keys, so we need to compare their
				 * lowest uncommon keys.
				 */
				JsonbIterator *it;
				JsonbIteratorToken tok;
				JsonbValue	jbvValBuf;
				PyObject   *max_key = differing_key ? differing_key : key;

				key = NULL;

				if (!res)
					res = 1;

				it = JsonbIteratorInit(jbc);

				while ((tok = JsonbIteratorNext(&it, &jbvKey, true)) != WJB_DONE)
				{
					if (tok != WJB_KEY)
						continue;

					if (JsonbIteratorNext(&it, &jbvValBuf, true) != WJB_VALUE)
						elog(ERROR, "unexpected jsonb iterator state");

					Py_XDECREF(key);

					key = PLyObject_FromJsonbValue(&jbvKey);

					if (!key || PyObject_Cmp(key, max_key, &cmp) < 0)
					{
						res = -2;	/* error */
						break;
					}

					if (cmp < 0)
					{
						int			contains = PyDict_Contains(other, key);

						if (contains < 0)
						{
							res = -2;	/* error */
							break;
						}

						if (!contains)
						{
							res = -1;	/* jsonb contains lower uncommon key */
							break;
						}
					}
				}

				Py_XDECREF(key);
				break;
			}

			if (res)
				continue;	/* result is already known, compare only key sets */

			value2 = PLyObject_FromJsonbValue(jbvVal);

			if (!value2 || PyObject_Cmp(value2, value, &cmp) < 0)
			{
				Py_XDECREF(value2);
				res = -2;	/* error */
				break;
			}

			Py_DECREF(value2);

			if (cmp)
			{
				res = cmp > 0 ? 1 : -1;

				if (i < pcount - 1)
				{
					differing_key = key;
					Py_INCREF(differing_key);
				}

				/* continue comparison because objects can have uncommon keys */
			}
		}
	}
	PG_CATCH();
	{
		Py_DECREF(items_v);
		Py_XDECREF(differing_key);
		PG_RE_THROW();
	}
	PG_END_TRY();

	Py_DECREF(items_v);
	Py_XDECREF(differing_key);

	return res;
}

static int
PLyJsonb_compare(PyObject *self, PyObject *other)
{
	PLyJsonb   *jb = (PLyJsonb *) self;
	JsonbContainer *jbc = jb->data;
	int			res;

	/* Compare to lists and dicts without transformation. */
	if (PyList_Check(other))
		return PLyJsonb_compareToList(jbc, other);
	else if (PyDict_Check(other))
		return PLyJsonb_compareToDict(jbc, other);

	/* Transform jsonb into Python dict or list, and then compare. */
	if (!(self = PLyObject_FromJsonbContainer(jbc)) ||
		PyObject_Cmp(self, other, &res) < 0)
		res = -2;	/* error */
	else if (res > 0)
		res = 1;
	else if (res < 0)
		res = -1;

	Py_XDECREF(self);

	return res;
}

/* Implementation of tp_richcompare() for JsonbArray and JsonbObject. */
static PyObject *
PLyJsonb_richcompare(PyObject *self, PyObject *other, int op)
{
	int			res = PLyJsonb_compare(self, other);

	if (res < -1)
		return NULL;	/* error */

	switch (op)
	{
		case Py_EQ:
			res = (res == 0);
			break;
		case Py_NE:
			res = (res != 0);
			break;
		case Py_LE:
			res = (res <= 0);
			break;
		case Py_GE:
			res = (res >= 0);
			break;
		case Py_LT:
			res = (res == -1);
			break;
		case Py_GT:
			res = (res == 1);
			break;
		default:
			elog(ERROR, "unrecognized tp_richcompare() operation: %d", op);
			break;
	}

	return PyBool_FromLong(res);
}

/* Get the slice of a JsonbArray. */
static PyObject *
PLyJsonbArray_slice(PyObject *self, PyObject *slice)
{
	PLyJsonb   *jb = (PLyJsonb *) self;
	JsonbContainer *jbc = jb->data;
	PyObject   *result;
	Py_ssize_t	length = JsonContainerSize(jbc);
	Py_ssize_t	start;
	Py_ssize_t	stop;
	Py_ssize_t	step;
	Py_ssize_t	slicelen;

	if (!PySlice_Check(slice))
		return PyErr_Format(PyExc_IndexError, "slice expected in __getslice__");

	if (PySlice_GetIndicesEx(
#if PY_VERSION_HEX < 0x03020000
							 (PySliceObject *)
#endif
							 slice, length, &start, &stop, &step, &slicelen))
		return NULL;

	if (!step)
		return PyErr_Format(PyExc_ValueError, "slice step cannot be zero");

	result = PyList_New(0);

	if (!result)
		return NULL;

	PG_TRY();
	{
		Py_ssize_t i;

		for (i = start; step > 0 ? i < stop : i > stop; i += step)
		{
			PyObject   *elem = PLyJsonbArray_item(self, i);

			if (!elem)
			{
				Py_DECREF(result);
				return NULL;
			}

			PyList_Append(result, elem);
			Py_DECREF(elem);
		}
	}
	PG_CATCH();
	{
		Py_DECREF(result);
		PG_RE_THROW();
	}
	PG_END_TRY();

	return result;
}

/* Implementation of JsonbArray's mp_subscript() mapping method */
static PyObject *
PLyJsonbArray_subscript(PyObject *self, PyObject *key)
{
	if (PyIndex_Check(key))
	{
		Py_ssize_t	i = PyNumber_AsSsize_t(key, PyExc_IndexError);

		if (i == -1 && PyErr_Occurred())
			return NULL;

		return PLyJsonbArray_item(self, i);
	}
	else if (PySlice_Check(key))
	{
		return PLyJsonbArray_slice(self, key);
	}
	else
	{
		return PyErr_Format(PyExc_TypeError,
							"JsonbArray indices must be integers or slices, not %.200s",
							key->ob_type->tp_name);
	}
}

/* Subroutine for JsonbArray's index() and count() methods */
static PyObject *
PLyJsonbArray_index_count(PyObject *self, PyObject *value, bool index)
{
	PLyJsonb   *jb = (PLyJsonb *) self;
	JsonbContainer *jbc = jb->data;
	JsonbIterator *it;
	JsonbIteratorToken r;
	JsonbValue	v;
	Py_ssize_t	count = 0;
	Py_ssize_t	i = 0;

	it = JsonbIteratorInit(jbc);

	while ((r = JsonbIteratorNext(&it, &v, true)) != WJB_DONE)
	{
		if (r == WJB_ELEM)
		{
			PyObject   *elem = PLyJsonbArray_get_or_transform_item(jb, i, &v);
			int			cmp;

			if (!elem)
				return NULL;	/* error */

			cmp = PyObject_RichCompareBool(elem, value, Py_EQ);

			Py_DECREF(elem);

			if (cmp < 0)
				return NULL;	/* error */

			if (cmp > 0)
			{
				if (index)
					return PyLong_FromSsize_t(i);
				count++;
			}

			i++;
		}
	}

	if (index)
		return PyErr_Format(PyExc_ValueError, "value is not in JsonbArray");

	return PyLong_FromSsize_t(count);
}

/* Implementation of JsonbArray.index() method */
static PyObject *
PLyJsonbArray_index(PyObject *self, PyObject *value)
{
	return PLyJsonbArray_index_count(self, value, true);
}

/* Implementation of JsonbArray.count() method */
static PyObject *
PLyJsonbArray_count(PyObject *self, PyObject *value)
{
	return PLyJsonbArray_index_count(self, value, false);
}

/* Implementation of JsonbArray type's tp_iter() */
static PyObject *
PLyJsonbArray_iter(PyObject *self)
{
	PLyJsonb *arr = (PLyJsonb *) self;

	if (arr->fully_cached)
		return PyObject_GetIter(arr->cache);

	return PLyJsonb_makeIter(self, PLPY_JSONB_ITER_ELEMENTS);
}

/* Implementation of Mapping protocol for JsonbArray. */
static PyMappingMethods
PLyJsonbArray_MappingMethods =
{
	.mp_length = PLyJsonb_length,
	.mp_subscript = PLyJsonbArray_subscript,
};

/* Implementation of standard Python read-only array methods for JsonbArray. */
static PyMethodDef
PLyJsonbArray_methods[] =
{
	{ "count", PLyJsonbArray_count, METH_O, NULL },
	{ "index", PLyJsonbArray_index, METH_O, NULL },
	{ NULL },
};

/* Type object for JsonbObject class */
PyTypeObject
PLyJsonbObject_Type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = PLPY_JSONB_TYPE_NAME("JsonbObject"),
	.tp_doc = "Read-only wrapper for PostgreSQL jsonb objects",
	.tp_basicsize = sizeof(PLyJsonb),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = (newfunc) PLyJsonb_new,
	.tp_dealloc = (destructor) PLyJsonb_dealloc,
	.tp_methods = PLyJsonbObject_methods,
	.tp_repr = (reprfunc) PLyJsonb_repr,
	.tp_str = (reprfunc) PLyJsonb_repr,
	.tp_richcompare = PLyJsonb_richcompare,
	.tp_iter = PLyJsonbObject_iter,
	.tp_as_sequence = &PLyJsonbObject_SequenceMethods,
	.tp_as_mapping = &PLyJsonbObject_MappingMethods,
};

/* Type object for JsonbArray class */
PyTypeObject
PLyJsonbArray_Type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = PLPY_JSONB_TYPE_NAME("JsonbArray"),
	.tp_doc = "Read-only wrapper for PostgreSQL jsonb arrays",
	.tp_basicsize = sizeof(PLyJsonb),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = (newfunc) PLyJsonb_new,
	.tp_dealloc = (destructor) PLyJsonb_dealloc,
	.tp_methods = PLyJsonbArray_methods,
	.tp_repr = (reprfunc) PLyJsonb_repr,
	.tp_str = (reprfunc) PLyJsonb_repr,
	.tp_richcompare = PLyJsonb_richcompare,
	.tp_iter = PLyJsonbArray_iter,
	.tp_as_sequence = &PLyJsonbArray_SequenceMethods,
	.tp_as_mapping = &PLyJsonbArray_MappingMethods,
};

/* Type object for JsonbIterator class */
static PyTypeObject
PLyJsonbIter_Type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = PLPY_JSONB_TYPE_NAME("JsonbIterator"),
	.tp_doc = "Wrapper for PostgreSQL jsonb iterators",
	.tp_basicsize = sizeof(PLyJsonbIter),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,// | Py_TPFLAGS_HAVE_GC,
	.tp_new = PLyJsonbIter_new,
	.tp_dealloc = PLyJsonbIter_dealloc,
	.tp_iter = &PLyJsonbIter_iter,
	.tp_iternext = &PLyJsonbIter_iternext,
};

PyObject *
PLyJsonb_FromJsonbContainer(JsonbContainer *jbc, size_t len)
{
	PLyJsonb   *res;
	PyTypeObject *type;

	/* Jsonb scalars are not wrapped. */
	if (JsonContainerIsScalar(jbc))
		return PLyObject_FromJsonbContainer(jbc);

	/* Wrap jsonb arrays and objects. */
	type = JsonContainerIsObject(jbc)
		? &PLyJsonbObject_Type : &PLyJsonbArray_Type;

	PyType_Ready(type);

	res = (PLyJsonb *) type->tp_new(type, NULL, NULL);

	if (!res)
		return NULL;

	res->data = memcpy(PyMem_Malloc(len), jbc, len);
	res->len = len;
	res->cache = JsonContainerIsObject(jbc) ? PyDict_New() : PyList_New(JsonContainerSize(jbc));
	res->ncached = 0;
	res->fully_cached = !JsonContainerSize(jbc);

	return (PyObject *) res;
}

JsonbValue *
PLyJsonb_ToJsonbValue(PyObject *obj, JsonbValue *jbv, bool copy)
{
	PLyJsonb *jb = (PLyJsonb *) obj;

	Assert(!JsonContainerIsScalar(jb->data));

	jbv->type = jbvBinary;
	jbv->val.binary.data = copy ? memcpy(palloc(jb->len), jb->data, jb->len) : jb->data;
	jbv->val.binary.len = jb->len;

	return jbv;
}
