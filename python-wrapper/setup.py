from distutils.core import setup, Extension

pypre = Extension('pypre',
                libraries = ['pre-afgh-relic', 'relic'],
                runtime_library_dirs = ['/usr/local/lib', '/opt/lib'],
                sources = ['pre_python.c'])

setup(name='pypre', ext_modules=[pypre])
