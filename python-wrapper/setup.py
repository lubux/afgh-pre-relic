from distutils.core import setup, Extension

pre = Extension('pre',
                include_dirs = ['/usr/local/include'],
                libraries = ['relic'],
                library_dirs = ['/usr/local/lib'],
                sources = ['pre_python.c', '../pre/pre-afgh-relic.c'])

setup(ext_modules=[pre])
