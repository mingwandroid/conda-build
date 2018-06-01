#!/bin/sh

if [[ ${target_platform} =~ osx-64 ]]; then
  TO_STATIC=
  TO_DYNAMIC=
  LIBNAME=${PREFIX}/lib/libz.a
  LIBNAME=${BUILD_PREFIX}/lib/libz.a
else
  TO_STATIC=-Wl,-Bstatic
  TO_DYNAMIC=-Wl,-Bdynamic
  LIBNAME=${BUILD_PREFIX}/lib/libz.a
fi
INCLUDES=-I${BUILD_PREFIX}/include

[[ -d ${PREFIX}/bin ]] || mkdir -p ${PREFIX}/bin

${CC} main.c -o ${PREFIX}/bin/main ${CFLAGS} ${INCLUDES} ${TO_STATIC} ${LIBNAME} ${TO_DYNAMIC}
