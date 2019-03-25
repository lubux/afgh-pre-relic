from distutils.core import setup, Extension

pypre = Extension('pypre',
                libraries = ['relic'],
                runtime_library_dirs = ['/usr/local/lib', '/opt/lib'],
                sources = ['pre_python.c', '../pre/encoding.c', '../pre/encryption.c', '../pre/keygen.c', '../pre/utils.c'])

setup(name='pypre', ext_modules=[pypre])
