from distutils.core import setup, Extension

setup(name='pypre',
      ext_modules=[
          Extension('pypre',
              libraries = ['pre-afgh-relic', 'relic'],
              runtime_library_dirs = ['/usr/local/lib', '/opt/lib'],
              sources = ['pre_python.c'],
              extra_compile_args=['-std=c99']
          )
    ]
)
