#!/bin/bash

conda run -p ${PREFIX} --debug-wrapper-scripts python -v --version | grep ${PY_VER}
if [[ ! $? ]]; then
  echo "ERROR :: conda run runs the wrong python (expected ${PY_VER})"
  exit 1
else
  echo "GOOD :: conda run runs the correct python (${PY_VER})"
fi
