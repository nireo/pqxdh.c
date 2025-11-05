project('pqxdh', 'c',
  version: '0.1.0',
  default_options: ['warning_level=3', 'c_std=c11']
)

cmake = import('cmake')

# System libsodium
libsodium_dep = dependency('libsodium')

# Subproject liboqs (0.14.0)
liboqs_subproj = cmake.subproject('liboqs',
  cmake_options: [
    '-DOQS_BUILD_ONLY_LIB=ON',
    '-DBUILD_SHARED_LIBS=OFF',
    '-DOQS_MINIMAL_BUILD=KEM_ml_kem_1024',
  ]
)
liboqs_dep = liboqs_subproj.dependency('oqs')

executable('pqxdh',
  'src/main.c',
  dependencies: [libsodium_dep, liboqs_dep]
)
