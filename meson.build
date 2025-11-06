project('pqxdh', 'c',
  version: '0.1.0',
  default_options: [
    'warning_level=3',
    'c_std=c11',
    'default_library=static', 
  ]
)

cmake = import('cmake')
pkgconfig = import('pkgconfig')

libsodium_dep = dependency('libsodium')

liboqs_subproj = cmake.subproject('liboqs',
  cmake_options: [
    '-DOQS_BUILD_ONLY_LIB=ON',
    '-DBUILD_SHARED_LIBS=OFF',
    '-DOQS_MINIMAL_BUILD=KEM_ml_kem_1024',
  ]
)
liboqs_dep = liboqs_subproj.dependency('oqs')

public_inc = include_directories('include')

pqxdh_lib = library('pqxdh',
  sources: [
    'src/pqxdh.c',
  ],
  include_directories: public_inc,
  dependencies: [libsodium_dep, liboqs_dep],
  version: meson.project_version(),
  install: true
)

install_headers(
  'include/pqxdh/pqxdh.h',
  subdir: 'pqxdh'
)

pqxdh_dep = declare_dependency(
  include_directories: public_inc,
  link_with: pqxdh_lib,
  dependencies: [libsodium_dep, liboqs_dep],
)

pkgconfig.generate(
  name: 'pqxdh',
  filebase: 'pqxdh',
  description: 'PQXDH implementation based on Signal spec using libsodium + liboqs',
  version: meson.project_version(),
  libraries: pqxdh_lib,
  subdirs: 'pqxdh',
  requires: ['libsodium'],
)

if get_option('build_cli')
  executable('pqxdh-cli',
    'src/main.c',
    dependencies: [pqxdh_dep],
    install: true
  )
endif

subdir('tests')
