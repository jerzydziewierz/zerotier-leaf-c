# SPDX-License-Identifier: Apache-2.0
if(CONFIG_ZTL)
  if(NOT CONFIG_CSPRNG_ENABLED OR CONFIG_TEST_CSPRNG_GENERATOR)
    message(FATAL_ERROR "zerotier-leaf-c needs a cryptographically secure random source that is not the test generator")
  endif()
  zephyr_library_named(zerotier_leaf_c)
  zephyr_library_sources(
    ../src/wire.c ../src/reasm.c ../src/rx.c ../src/salsa.c ../src/poly.c ../src/auth.c
    ../src/lz4.c ../src/dict.c ../src/leaf.c
    ztl_zephyr.c)
  zephyr_library_sources_ifdef(CONFIG_ZTL_SHELL ztl_shell.c)
  zephyr_library_include_directories(../src)
  # Applications include <ztl_zephyr.h> and <ztl/leaf.h>.
  zephyr_include_directories(include ../include)
  # The leaf is built as it is proved: ISO C11, all warnings on.
  zephyr_library_compile_options(-std=c11 -Wall -Wextra -fstack-usage)
endif()
