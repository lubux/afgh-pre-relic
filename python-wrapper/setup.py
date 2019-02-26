from distutils.core import setup, Extension

pypre = Extension('pypre',
                libraries = ['relic'],
                runtime_library_dirs = ['/usr/local/lib', '/opt/lib'],
                sources = ['pre_python.c', '../pre/pre-afgh-relic.c'])

setup(name='pypre', ext_modules=[pypre])
