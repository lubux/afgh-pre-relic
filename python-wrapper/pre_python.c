#include <Python.h>

#include "pre-afgh-relic.h"

/*
int encoded_key_size = 721;
int encoded_msg_size = 384;
int encoded_token_size = 1;
int encoded_cipher_size = 630;
*/

void dump_hex(const char* label, char* bytes, int n) {
    printf("%s:\n", label);
    for (int i = 0; i < n; i++) {
        printf("%02X", bytes[i]);
    }
    printf("\n");
    printf("\n");
}

void* error(const char* context, const char* failure) {
    char err_msg[14+strlen(context)+strlen(failure)];
    sprintf(err_msg, "%s :: failed to %s", context, failure);
    PyErr_SetString(PyExc_RuntimeError, err_msg);
    return NULL;
}

static PyObject* py_msg_to_ints(PyObject* self, PyObject* args)
{
    const char* err_context = "py_msg_to_ints";
    char msg_bytes[384];
    gt_t msg;
    uint8_t ret[16];

    if (!PyArg_ParseTuple(args, "y*", &msg_bytes)) {
        return error(err_context, "parse args");
    }

    if (decode_msg(msg, msg_bytes, 384) != STS_OK) {
        return error(err_context, "decode message");
    }
    if (pre_map_to_key(ret, 16, msg) != STS_OK) {
        return error(err_context, "map message to integers");
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

static PyObject* py_generate_msg(PyObject* self)
{
    const char* err_context = "py_generate_msg";
    gt_t msg;
    int encoded_msg_size;

    if (pre_rand_message(msg) != STS_OK) {
        return error(err_context, "generate random message");
    }

    encoded_msg_size = get_encoded_msg_size(msg);
    char msg_bytes[encoded_msg_size];
    if (encode_msg(msg_bytes, encoded_msg_size, msg) != STS_OK) {
        return error(err_context, "encode message");
    }

    return Py_BuildValue("y#", msg_bytes, encoded_msg_size);
}

static PyObject* py_generate_token(PyObject* self, PyObject* args)
{
    const char* err_context = "py_generate_token";
    char from_key_bytes[721], to_key_bytes[721];
    pre_keys_t from_key, to_key;
    pre_re_token_t token;
    int encoded_token_size;

    if (!PyArg_ParseTuple(args, "y*y*", &from_key_bytes, &to_key_bytes)) {
        return error(err_context, "parse_arguments");
    }

    dump_hex("from_key in generate_token", from_key_bytes, 721);

    if (decode_key(from_key, from_key_bytes, 721) != STS_OK) {
        return error(err_context, "decode 'from' key");
    }
    if (decode_key(to_key, to_key_bytes, 721) != STS_OK) {
        return error(err_context, "decode 'to' key");
    }
    if (pre_generate_re_token(token, from_key, to_key->pk_2) != STS_OK) {
        return error(err_context, "generate re-encryption token");
    }

    encoded_token_size = get_encoded_token_size(token);
    char token_bytes[encoded_token_size];
    if (encode_token(token_bytes, encoded_token_size, token) != STS_OK) {
        return error(err_context, "encode token");
    }

    return Py_BuildValue("y#", token_bytes, encoded_token_size);
}

static PyObject* py_apply_token(PyObject* self, PyObject* args)
{
    const char* err_context = "py_apply_token";
    char token_bytes[1], in_cipher_bytes[384];
    pre_re_token_t token;
    pre_ciphertext_t in_cipher, out_cipher;
    int encoded_cipher_size;

    if (!PyArg_ParseTuple(args, "y*y*", &token_bytes, &in_cipher_bytes)) {
        return error(err_context, "parse arguments");
    }

    if (decode_token(token, token_bytes, 1) != STS_OK) {
        return error(err_context, "decode token");
    }
    if (decode_cipher(in_cipher, in_cipher_bytes, 384) != STS_OK) {
        return error(err_context, "decode ciphertext");
    }

    if (pre_re_apply(token, out_cipher, in_cipher) != STS_OK) {
        return error(err_context, "apply re-encryption token");
    }

    encoded_cipher_size = get_encoded_cipher_size(out_cipher);
    char out_cipher_bytes[encoded_cipher_size];
    if (encode_cipher(out_cipher_bytes, encoded_cipher_size, out_cipher) != STS_OK) {
        return error(err_context, "encode ciphertext");
    }

    return Py_BuildValue("y#", encoded_cipher_size);
}

static PyObject* py_decrypt(PyObject* self, PyObject* args)
{
    const char* err_context = "py_decrypt";
    char key_bytes[721], cipher_bytes[630];
    gt_t msg;
    pre_keys_t key;
    pre_ciphertext_t cipher;
    int encoded_msg_size;

    if (!PyArg_ParseTuple(args, "y*y*", &key_bytes, &cipher_bytes)) {
        return error(err_context, "parse arguments");
    }

    if (decode_key(key, key_bytes, 721) != STS_OK) {
        return error(err_context, "decode key");
    }
    if (decode_cipher(cipher, cipher_bytes, 384) != STS_OK) {
        return error(err_context, "decode ciphertext");
    }

    if (pre_decrypt(msg, key, cipher) != STS_OK) {
        return error(err_context, "decrypt ciphertext");
    }

    encoded_msg_size = get_encoded_msg_size(msg);
    char msg_bytes[encoded_msg_size];
    if (encode_msg(msg_bytes, encoded_msg_size, msg) != STS_OK) {
        return error(err_context, "encode message");
    }

    return Py_BuildValue("y#", msg_bytes, encoded_msg_size);
}

static PyObject* py_encrypt(PyObject* self, PyObject* args)
{
    const char* err_context = "py_encrypt";
    char key_bytes[721], msg_bytes[384];
    gt_t msg;
    pre_keys_t key;
    pre_ciphertext_t cipher;
    int encoded_cipher_size;

    if (!PyArg_ParseTuple(args, "y*y*", &key_bytes, &msg_bytes)) {
        return error(err_context, "parse arguments");
    }

    if(decode_key(key, key_bytes, 721) != STS_OK) {
        return error(err_context, "decode key");
    }
    if (decode_msg(msg, msg_bytes, 384) != STS_OK) {
        return error(err_context, "decode message");
    }

    if (pre_encrypt(cipher, key, msg) != STS_OK) {
        return error(err_context, "encrypt message");
    }

    encoded_cipher_size = get_encoded_cipher_size(cipher);
    char cipher_bytes[encoded_cipher_size];

    if (encode_cipher(cipher_bytes, encoded_cipher_size, cipher) != STS_OK) {
        return error(err_context, "encode ciphertext");
    }

    return Py_BuildValue("y#", cipher_bytes, encoded_cipher_size);
}

static PyObject* py_generate_key(PyObject* self)
{
    const char* err_context = "py_generate_key";
    pre_keys_t key;
    int encoded_key_size;

    if (pre_generate_keys(key) != STS_OK) {
        return error(err_context, "generate key");
    }

    encoded_key_size = get_encoded_key_size(key);
    char encoded_key[encoded_key_size];
    if (encode_key(encoded_key, encoded_key_size, key) != STS_OK) {
        return error(err_context, "encode key");
    }

    dump_hex("key in generate_key", encoded_key, encoded_key_size);
    return Py_BuildValue("y#", encoded_key, encoded_key_size);
}

static PyMethodDef pre_methods[] = {
    {"generate_key", (PyCFunction)py_generate_key, METH_NOARGS, NULL},
    {"encrypt", (PyCFunction)py_encrypt, METH_VARARGS, NULL},
    {"decrypt", (PyCFunction)py_decrypt, METH_VARARGS, NULL},
    {"generate_token", (PyCFunction)py_generate_token, METH_VARARGS, NULL},
    {"apply_token", (PyCFunction)py_apply_token, METH_VARARGS, NULL},
    {"generate_msg", (PyCFunction)py_generate_msg, METH_NOARGS, NULL},
    {"msg_to_ints", (PyCFunction)py_msg_to_ints, METH_VARARGS, NULL},
};

static struct PyModuleDef preDef =
{
    PyModuleDef_HEAD_INIT,
    "pre", /* name of module */
    NULL,  /* module documentation, may be NULL */
    -1,    /* size of per-interpreter state of the module, or -1 if the module keeps state in global variables. */
    pre_methods
};

PyMODINIT_FUNC PyInit_pre(void)
{
    pre_init();
    return PyModule_Create(&preDef);
}
