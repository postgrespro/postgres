#include "postgres.h"

#include "jsonb_plpython.h"
#include "numeric_plpython.h"
#include "plpy_elog.h"
#include "plpy_typeio.h"
#include "utils/builtins.h"

#define PLyObject_AsString (PLyObject_AsString_p)
#define PLyUnicode_FromStringAndSize (PLyUnicode_FromStringAndSize_p)
#undef PLy_elog
#define PLy_elog (PLy_elog_impl_p)

typedef struct PLyNumeric
{
	PyObject_HEAD
	Numeric		value;
} PLyNumeric;

static PyTypeObject PLyNumericType;

static PyObject *
PLyNumeric_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	PLyNumeric *num = (PLyNumeric *) type->tp_alloc(type, 0);
	PyObject   *str;

	if (!PyArg_ParseTuple(args, "s", &str))
		return NULL;

	num->value = DatumGetNumeric(
		DirectFunctionCall3(numeric_in,
							CStringGetDatum(str),
							ObjectIdGetDatum(InvalidOid),
							Int32GetDatum(-1)));

	return (PyObject *) num;
}

static void
PLyNumeric_dealloc(PyObject *self)
{
	PLyNumeric *num = (PLyNumeric *) self;

	PyMem_Free(num->value);

	Py_TYPE(self)->tp_free(self);
}

static PyObject *
PLyNumeric_str(PLyNumeric *num)
{
	char	   *str =
		DatumGetCString(DirectFunctionCall1(numeric_out,
											NumericGetDatum(num->value)));
	PyObject *res = PyUnicode_FromStringAndSize(str, strlen(str));

	pfree(str);

	return res;
}

static PyObject *
PLyNumeric_repr(PLyNumeric *num)
{
	char	   *str =
		DatumGetCString(DirectFunctionCall1(numeric_out,
											NumericGetDatum(num->value)));
	PyObject   *res = PyUnicode_FromFormat("Numeric('%s')", str);

	pfree(str);

	return res;
}

PyObject *
PLyObject_FromNumeric(Numeric num)
{
	PLyNumeric *n;

	PyType_Ready(&PLyNumericType);

	n = (PLyNumeric *) PLyNumericType.tp_alloc(&PLyNumericType, 0);

	if (!n)
		return NULL;

	n->value = PyMem_Malloc(VARSIZE(num));

	if (!n->value)
	{
		Py_DECREF((PyObject *) n);
		return NULL;
	}

	memcpy(n->value, num, VARSIZE(num));

	return (PyObject *) n;
}

int
PLyNumeric_Check(PyObject *obj)
{
	return PyObject_TypeCheck(obj, &PLyNumericType);
}

Numeric
PLyNumeric_ToNumeric(PyObject *obj)
{
	PLyNumeric *num = (PLyNumeric *) obj;
	Numeric		res = palloc(VARSIZE(num->value));

	memcpy(res, num->value, VARSIZE(num->value));

	return res;
}

static PyObject *
PLyNumeric_power(PyObject *base, PyObject *pow, PyObject *mod)
{
	Numeric		res = DatumGetNumeric(DirectFunctionCall2(numeric_power,
								NumericGetDatum(((PLyNumeric *) base)->value),
								NumericGetDatum(((PLyNumeric *) pow)->value)));

	if (mod && mod != Py_None)
		res = DatumGetNumeric(DirectFunctionCall2(numeric_mod,
								NumericGetDatum(res),
								NumericGetDatum(((PLyNumeric *) mod)->value)));

	return PLyObject_FromNumeric(res);
}

static int
PLyNumeric_nonzero(PyObject *num)
{
	return !DatumGetBool(DirectFunctionCall2(numeric_eq,
								NumericGetDatum(((PLyNumeric *) num)->value),
								DirectFunctionCall1(int4_numeric, Int32GetDatum(0))));
}

static PyObject *
PLyNumeric_long(PyObject *obj)
{
	PyObject   *res;
	PLyNumeric *num = (PLyNumeric *) obj;
	Datum		truncated;
	char	   *str;

	truncated = DirectFunctionCall2(numeric_trunc,
									NumericGetDatum(num->value),
									Int32GetDatum(0));
	str = DatumGetCString(DirectFunctionCall1(numeric_out, truncated));
	res = PyLong_FromString(str, NULL, 10);
	pfree(str);

	return res;
}

static PyObject *
PLyNumeric_int(PyObject *obj)
{
	PLyNumeric *num = (PLyNumeric *) obj;
	Numeric		truncated;
	int64		intval;

	if (numeric_to_exact_int64(num->value, &intval))
#ifndef HAVE_LONG_INT_64
					if ((long long) intval == intval)
#endif
						return PyLong_FromLongLong((long long) intval);

	truncated = DatumGetNumeric(
		DirectFunctionCall2(numeric_trunc,
							NumericGetDatum(num->value),
							Int32GetDatum(0)));

	if (numeric_to_exact_int64(truncated, &intval))
#ifndef HAVE_LONG_INT_64
					if ((long long) intval == intval)
#endif
						return PyLong_FromLongLong((long long) intval);

	return PLyNumeric_long(obj);
}

static PyObject *
PLyNumeric_float(PyObject *obj)
{
	PLyNumeric *num = (PLyNumeric *) obj;
	float8		d = DatumGetFloat8(
		DirectFunctionCall1(numeric_float8, NumericGetDatum(num->value)));

	return PyFloat_FromDouble(d);
}

Numeric
PLyNumber_ToNumeric(PyObject *obj)
{
	Numeric		num;
	char	   *str;

	if (PLyNumeric_Check(obj))
		return PLyNumeric_ToNumeric(obj);

	if (PyLong_Check(obj))
	{
		long long	val = PyLong_AsLongLong(obj);

		if (val != -1 || !PyErr_Occurred())
			return DatumGetNumeric(DirectFunctionCall1(int8_numeric,
													Int64GetDatum((int64) val)));

		PyErr_Clear();
	}

	str = PLyObject_AsString(obj);

	PG_TRY();
	{
		Datum		numd;

		numd = DirectFunctionCall3(numeric_in,
								   CStringGetDatum(str),
								   ObjectIdGetDatum(InvalidOid),
								   Int32GetDatum(-1));
		num = DatumGetNumeric(numd);
	}
	PG_CATCH();
	{
		ereport(ERROR,
				(errcode(ERRCODE_DATATYPE_MISMATCH),
				 (errmsg("could not convert value \"%s\" to jsonb", str))));
	}
	PG_END_TRY();

	pfree(str);

	return num;
}

static PyObject *
PLyNumeric_FromNumber(PyObject *num)
{
	return PLyObject_FromNumeric(PLyNumber_ToNumeric(num));
}

static int
PLyNumeric_coerce(PyObject **p1, PyObject **p2)
{
	if (!PyNumber_Check(*p2))
		return 1; /* coercion is not possible */

	if (PLyNumeric_Check(*p2))
	{
		Py_INCREF(*p1);
		Py_INCREF(*p2);
		return 0;
	}

	*p2 = PLyNumeric_FromNumber(*p2);

	if (!*p2)
		return -1;

	Py_INCREF(*p1);
	return 0;
}

static PyObject *
PLyNumeric_richcompare(PyObject *self, PyObject *other, int op)
{
	Numeric		n1 = ((PLyNumeric *) self)->value;
	Numeric		n2;
	int			r;

	if (!PyNumber_Check(other))
	{
		Py_INCREF(Py_NotImplemented);
		return Py_NotImplemented;
	}

	n2 = PLyNumber_ToNumeric(other);

	r = DatumGetInt32(DirectFunctionCall2(numeric_cmp,
										  NumericGetDatum(n1),
										  NumericGetDatum(n2)));

	switch (op)
	{
		case Py_EQ:
			r = (r == 0);
			break;
		case Py_NE:
			r = (r != 0);
			break;
		case Py_LE:
			r = (r <= 0);
			break;
		case Py_GE:
			r = (r >= 0);
			break;
		case Py_LT:
			r = (r == -1);
			break;
		case Py_GT:
			r = (r == 1);
			break;
	}

	return PyBool_FromLong(r);
}

#define PLyNumeric_binary_method(name) \
static PyObject * \
PLyNumeric_ ## name(PyObject *n1, PyObject *n2) \
{ \
	return PLyObject_FromNumeric(DatumGetNumeric(DirectFunctionCall2(numeric_ ## name, \
									NumericGetDatum(((PLyNumeric *) n1)->value), \
									NumericGetDatum(((PLyNumeric *) n2)->value)))); \
}

#define PLyNumeric_unary_method(name) \
static PyObject * \
PLyNumeric_ ## name(PyObject *n1) \
{ \
	return PLyObject_FromNumeric(DatumGetNumeric(DirectFunctionCall1(numeric_ ## name, \
									NumericGetDatum(((PLyNumeric *) n1)->value)))); \
}

PLyNumeric_binary_method(add)
PLyNumeric_binary_method(sub)
PLyNumeric_binary_method(mul)
PLyNumeric_binary_method(div)
PLyNumeric_binary_method(mod)

PLyNumeric_unary_method(uminus)
PLyNumeric_unary_method(uplus)
PLyNumeric_unary_method(abs)

static PyNumberMethods
PLyNumericNumberMethods =
{
	.nb_add = PLyNumeric_add,
	.nb_subtract = PLyNumeric_sub,
	.nb_multiply = PLyNumeric_mul,
	//.nb_divide = PLyNumeric_div,
	.nb_divmod = PLyNumeric_div,
	.nb_remainder = PLyNumeric_mod,
	.nb_power = PLyNumeric_power,
	//.nb_nonzero = PLyNumeric_nonzero,

	.nb_negative = PLyNumeric_uminus,
	.nb_positive = PLyNumeric_uplus,
	.nb_absolute = PLyNumeric_abs,

	//.nb_coerce = PLyNumeric_coerce,
	.nb_int = PLyNumeric_int,
	//.nb_long = PLyNumeric_long,
	.nb_float = PLyNumeric_float,
};

static PyTypeObject
PLyNumericType =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "Numeric",
	.tp_doc = "PG Numeric type",
	.tp_basicsize = sizeof(PLyNumeric),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = (newfunc) PLyNumeric_new,
	.tp_dealloc = (destructor) PLyNumeric_dealloc,
	.tp_repr = (reprfunc) PLyNumeric_repr,
	.tp_str = (reprfunc) PLyNumeric_str,
	.tp_richcompare = PLyNumeric_richcompare,
	.tp_as_number = &PLyNumericNumberMethods,
};

/*
 * numeric_to_plpython
 *
 * Transform Numeric datum to PyObject and return it as internal.
 */
PG_FUNCTION_INFO_V1(numeric_to_plpython);
Datum
numeric_to_plpython(PG_FUNCTION_ARGS)
{
	Numeric		num = PG_GETARG_NUMERIC(0);
	PyObject   *result = PLyObject_FromNumeric(num);

	PG_FREE_IF_COPY(num, 0);

	if (!result)
		PLy_elog(ERROR, "transformation from numeric to Python failed");

	return PointerGetDatum(result);
}

/*
 * plpython_to_numeric
 *
 * Transform python object to Numeric datum
 */
PG_FUNCTION_INFO_V1(plpython_to_numeric);
Datum
plpython_to_numeric(PG_FUNCTION_ARGS)
{
	PyObject   *obj = (PyObject *) PG_GETARG_POINTER(0);

	if (!PyNumber_Check(obj))
		PLy_elog(ERROR, "cannot convert Python %s to a numeric",
				 Py_TYPE(obj)->tp_name);

	PG_RETURN_NUMERIC(PLyNumber_ToNumeric(obj));
}
