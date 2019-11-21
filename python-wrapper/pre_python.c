#include <Python.h>

#include <sys/types.h>
#include <fcntl.h>

#include "pre-afgh-relic.h"

// convenience function to dump bytes as hex (same format as Python __str__)
void dump_hex(const char* label, char* bytes, int n) {
    printf("%s:\n", label);
    for (int i = 0; i < n; i++) {
        printf("%02x", (unsigned char)bytes[i]);
    }
    printf("\n");
    printf("\n");
}

void* error(const char* context, const char* failure) {
    char err_plaintext[14+strlen(context)+strlen(failure)];
    sprintf(err_plaintext, "%s :: failed to %s", context, failure);
    PyErr_SetString(PyExc_RuntimeError, err_plaintext);
    return NULL;
}

static PyObject* py_plaintext_to_ints(PyObject* self, PyObject* args)
{
    const char* err_context = "py_plaintext_to_ints";
    Py_buffer plaintext_buf;
    pre_plaintext_t plaintext;
    uint8_t ret[16];

    if (!PyArg_ParseTuple(args, "y*", &plaintext_buf)) {
        return error(err_context, "parse args");
    }

    if (decode_plaintext(plaintext, plaintext_buf.buf, (int)plaintext_buf.len) != RLC_OK) {
        return error(err_context, "decode plaintext");
    }

    if (pre_map_to_key(ret, 16, plaintext) != RLC_OK) {
        return error(err_context, "map plaintext to integers");
    }

    PyObject *l = PyList_New(16);
    if (!l) {
        return error(err_context, "initialize python list");
    }
    for (int i = 0; i < 16; i++) {
        PyObject *item = PyLong_FromLong(ret[i]);
        if (!item) {
            Py_DECREF(l);
            return error(err_context, "convert c int to python long");
        }
        PyList_SET_ITEM(l, i, item);
    }
    return l;
}

static PyObject* py_rand_plaintext(PyObject* self)
{
    const char* err_context = "py_rand_plaintext";
    pre_plaintext_t plaintext;
    int size;

    if (pre_rand_plaintext(plaintext) != RLC_OK) {
        return error(err_context, "generate random plaintext");
    }

    size = get_encoded_plaintext_size(plaintext);
    char plaintext_bytes[size];
    if (encode_plaintext(plaintext_bytes, size, plaintext) != RLC_OK) {
        return error(err_context, "encode plaintext");
    }

    return Py_BuildValue("y#", plaintext_bytes, size);
}

static PyObject* py_apply_token(PyObject* self, PyObject* args)
{
    const char* err_context = "py_apply_token";
    Py_buffer token_buf, ciphertext_buf;
    pre_token_t token;
    pre_ciphertext_t ciphertext;
    pre_re_ciphertext_t re_ciphertext;
    int size;

    if (!PyArg_ParseTuple(args, "y*y*", &token_buf, &ciphertext_buf)) {
        return error(err_context, "parse arguments");
    }

    if(decode_token(token, token_buf.buf, (int)token_buf.len) != RLC_OK) {
        return error(err_context, "decode token");
    }
    if(decode_ciphertext(ciphertext, ciphertext_buf.buf, (int)ciphertext_buf.len) != RLC_OK) {
        return error(err_context, "decode ciphertext");
    }

    if (pre_apply_token(re_ciphertext, token, ciphertext) != RLC_OK) {
        return error(err_context, "apply re-encryption token");
    }

    size = get_encoded_re_ciphertext_size(re_ciphertext);
    char re_ciphertext_bytes[size];
    if (encode_re_ciphertext(re_ciphertext_bytes, size, re_ciphertext) != RLC_OK) {
        return error(err_context, "encode re-encrypted ciphertext");
    }

    return Py_BuildValue("y#", re_ciphertext_bytes, size);
}

static PyObject* py_generate_token(PyObject* self, PyObject* args)
{
    const char* err_context = "py_generate_token";
    Py_buffer params_buf, sk_buf, pk_buf;
    pre_params_t params;
    pre_sk_t sk;
    pre_pk_t pk;
    pre_token_t token;
    int size;

    if (!PyArg_ParseTuple(args, "y*y*y*", &params_buf, &sk_buf, &pk_buf)) {
        return error(err_context, "parse arguments");
    }

    if(decode_params(params, params_buf.buf, (int)params_buf.len) != RLC_OK) {
        return error(err_context, "decode params");
    }
    if(decode_sk(sk, sk_buf.buf, (int)sk_buf.len) != RLC_OK) {
        return error(err_context, "decode sk");
    }
    if (decode_pk(pk, pk_buf.buf, (int)pk_buf.len) != RLC_OK) {
        return error(err_context, "decode pk");
    }

    if (pre_generate_token(token, params, sk, pk) != RLC_OK) {
        return error(err_context, "generate re-encryption token");
    }

    size = get_encoded_token_size(token);
    char token_bytes[size];
    if (encode_token(token_bytes, size, token) != RLC_OK) {
        return error(err_context, "encode token");
    }

    return Py_BuildValue("y#", token_bytes, size);
}

static PyObject* py_decrypt_re(PyObject* self, PyObject* args)
{
    const char* err_context = "py_decrypt_re";
    Py_buffer params_buf, sk_buf, re_ciphertext_buf;
    pre_params_t params;
    pre_sk_t sk;
    pre_re_ciphertext_t re_ciphertext;
    pre_plaintext_t plaintext;
    int size;

    if (!PyArg_ParseTuple(args, "y*y*y*", &params_buf, &sk_buf, &re_ciphertext_buf)) {
        return error(err_context, "parse arguments");
    }

    if(decode_params(params, params_buf.buf, (int)params_buf.len) != RLC_OK) {
        return error(err_context, "decode params");
    }
    if(decode_sk(sk, sk_buf.buf, (int)sk_buf.len) != RLC_OK) {
        return error(err_context, "decode sk");
    }
    if (decode_re_ciphertext(re_ciphertext, re_ciphertext_buf.buf, (int)re_ciphertext_buf.len) != RLC_OK) {
        return error(err_context, "decode re-encrypted ciphertext");
    }

    if (pre_decrypt_re(plaintext, params, sk, re_ciphertext) != RLC_OK) {
        return error(err_context, "decrypt re-encrypted ciphertext");
    }

    size = get_encoded_plaintext_size(plaintext);
    char plaintext_bytes[size];
    if (encode_plaintext(plaintext_bytes, size, plaintext) != RLC_OK) {
        return error(err_context, "encode plaintext");
    }

    return Py_BuildValue("y#", plaintext_bytes, size);
}

static PyObject* py_decrypt(PyObject* self, PyObject* args)
{
    const char* err_context = "py_decrypt";
    Py_buffer params_buf, sk_buf, ciphertext_buf;
    pre_params_t params;
    pre_sk_t sk;
    pre_ciphertext_t ciphertext;
    pre_plaintext_t plaintext;
    int size;

    if (!PyArg_ParseTuple(args, "y*y*y*", &params_buf, &sk_buf, &ciphertext_buf)) {
        return error(err_context, "parse arguments");
    }

    if(decode_params(params, params_buf.buf, (int)params_buf.len) != RLC_OK) {
        return error(err_context, "decode params");
    }
    if(decode_sk(sk, sk_buf.buf, (int)sk_buf.len) != RLC_OK) {
        return error(err_context, "decode sk");
    }
    if (decode_ciphertext(ciphertext, ciphertext_buf.buf, (int)ciphertext_buf.len) != RLC_OK) {
        return error(err_context, "decode ciphertext");
    }

    if (pre_decrypt(plaintext, params, sk, ciphertext) != RLC_OK) {
        return error(err_context, "decrypt ciphertext");
    }

    size = get_encoded_plaintext_size(plaintext);
    char plaintext_bytes[size];
    if (encode_plaintext(plaintext_bytes, size, plaintext) != RLC_OK) {
        return error(err_context, "encode plaintext");
    }

    return Py_BuildValue("y#", plaintext_bytes, size);
}

static PyObject* py_encrypt(PyObject* self, PyObject* args)
{
    const char* err_context = "py_encrypt";
    Py_buffer params_buf, pk_buf, plaintext_buf;
    pre_params_t params;
    pre_pk_t pk;
    pre_plaintext_t plaintext;
    pre_ciphertext_t ciphertext;
    int size;

    if (!PyArg_ParseTuple(args, "y*y*y*", &params_buf, &pk_buf, &plaintext_buf)) {
        return error(err_context, "parse arguments");
    }

    if(decode_params(params, params_buf.buf, (int)params_buf.len) != RLC_OK) {
        return error(err_context, "decode params");
    }
    if(decode_pk(pk, pk_buf.buf, (int)pk_buf.len) != RLC_OK) {
        return error(err_context, "decode pk");
    }
    if (decode_plaintext(plaintext, plaintext_buf.buf, (int)plaintext_buf.len) != RLC_OK) {
        return error(err_context, "decode plaintext");
    }

    if (pre_encrypt(ciphertext, params, pk, plaintext) != RLC_OK) {
        return error(err_context, "encrypt plaintext");
    }

    size = get_encoded_ciphertext_size(ciphertext);
    char ciphertext_bytes[size];

    if (encode_ciphertext(ciphertext_bytes, size, ciphertext) != RLC_OK) {
        return error(err_context, "encode ciphertext");
    }

    return Py_BuildValue("y#", ciphertext_bytes, size);
}

static PyObject* py_derive_pk(PyObject* self, PyObject* args)
{
    const char* err_context = __func__;
    Py_buffer params_buf, sk_buf;
    pre_params_t params;
    pre_sk_t sk;
    pre_pk_t pk;
    int size;

    if (!PyArg_ParseTuple(args, "y*y*", &params_buf, &sk_buf)) {
        return error(err_context, "parse arguments");
    }

    if(decode_params(params, params_buf.buf, (int)params_buf.len) != RLC_OK) {
        return error(err_context, "decode params");
    }
    if(decode_sk(sk, sk_buf.buf, (int)sk_buf.len) != RLC_OK) {
        return error(err_context, "decode sk");
    }

    if (pre_derive_pk(pk, params, sk) != RLC_OK) {
        return error(err_context, "generate pk");
    }

    size = get_encoded_pk_size(pk);
    char encoded_pk[size];
    if (encode_pk(encoded_pk, size, pk) != RLC_OK) {
        return error(err_context, "encode pk");
    }

    return Py_BuildValue("y#", encoded_pk, size);
}

static PyObject* py_generate_sk(PyObject* self, PyObject* args)
{
    const char* err_context = __func__;
    Py_buffer params_buf;
    pre_params_t params;
    pre_sk_t sk;
    int size;

    if (!PyArg_ParseTuple(args, "y*", &params_buf)) {
        return error(err_context, "parse arguments");
    }

    if(decode_params(params, params_buf.buf, (int)params_buf.len) != RLC_OK) {
        return error(err_context, "decode params");
    }

    if (pre_generate_sk(sk, params) != RLC_OK) {
        return error(err_context, "generate sk");
    }

    size = get_encoded_sk_size(sk);
    char encoded_sk[size];
    if (encode_sk(encoded_sk, size, sk) != RLC_OK) {
        return error(err_context, "encode sk");
    }

    return Py_BuildValue("y#", encoded_sk, size);
}

static PyObject* py_generate_params(PyObject* self)
{
    const char* err_context = __func__;
    pre_params_t params;
    int size;

    if (pre_generate_params(params) != RLC_OK) {
        return error(err_context, "generate params");
    }

    size = get_encoded_params_size(params);
    char encoded_params[size];
    if (encode_params(encoded_params, size, params) != RLC_OK) {
        return error(err_context, "encode params");
    }

    return Py_BuildValue("y#", encoded_params, size);
}

static PyMethodDef pre_methods[] = {
    {"generate_params", (PyCFunction)py_generate_params, METH_NOARGS, NULL},
    {"generate_sk", (PyCFunction)py_generate_sk, METH_VARARGS, NULL},
    {"derive_pk", (PyCFunction)py_derive_pk, METH_VARARGS, NULL},
    {"encrypt", (PyCFunction)py_encrypt, METH_VARARGS, NULL},
    {"decrypt", (PyCFunction)py_decrypt, METH_VARARGS, NULL},
    {"decrypt_re", (PyCFunction)py_decrypt_re, METH_VARARGS, NULL},
    {"generate_token", (PyCFunction)py_generate_token, METH_VARARGS, NULL},
    {"apply_token", (PyCFunction)py_apply_token, METH_VARARGS, NULL},
    {"rand_plaintext", (PyCFunction)py_rand_plaintext, METH_NOARGS, NULL},
    {"plaintext_to_ints", (PyCFunction)py_plaintext_to_ints, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef preDef =
{
    PyModuleDef_HEAD_INIT,
    "pypre", /* name of module */
    NULL,  /* module documentation, may be NULL */
    -1,    /* size of per-interpreter state of the module, or -1 if the module keeps state in global variables. */
    pre_methods
};

PyMODINIT_FUNC PyInit_pypre(void)
{
    int old_stdout, devnull;

    // suppress relic output
    fflush(stdout);
    old_stdout = dup(1);
    if (!(devnull = open("/dev/null", O_WRONLY))) {
        return error("pyinit_pre", "open /dev/null");
    }
    dup2(devnull, 1);
    close(devnull);
    pre_init(); // initialize proxy re-encryption library
    fflush(stdout);
    dup2(old_stdout, 1);
    close(old_stdout);

    return PyModule_Create(&preDef);
}
