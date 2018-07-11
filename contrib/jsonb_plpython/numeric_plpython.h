#include "postgres.h"
#include "plpython.h"
#include "utils/numeric.h"

extern PyObject *PLyObject_FromNumeric(Numeric num);
extern Numeric PLyNumeric_ToNumeric(PyObject *obj);
extern Numeric PLyNumber_ToNumeric(PyObject *obj);
extern int PLyNumeric_Check(PyObject *obj);

