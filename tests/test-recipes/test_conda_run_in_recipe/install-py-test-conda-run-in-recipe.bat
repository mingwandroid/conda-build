@echo ON
setlocal enabledelayedexpansion

set CONDA_TEST_SAVE_TEMPS=1
set CONDA_RUN=call conda run
:: set CONDA_RUN=C:\opt\conda\condabin\..\Scripts\conda.exe run
echo "(install-py-lief.bat) PATH just before conda run -p %RECIPE_DIR%\echo_path.bat is %PATH%"
where conda
%CONDA_RUN% -p %PREFIX% --debug-wrapper-scripts call %RECIPE_DIR%\echo_path.bat
echo "(install-py-lief.bat) Done call conda run -p"
if %errorlevel% neq 0 exit /b 1

%CONDA_RUN% -p %PREFIX% --debug-wrapper-scripts python --version

%CONDA_RUN% -p %PREFIX% --debug-wrapper-scripts python -v --version | findstr /r /c:%PY_VER%
if %errorlevel% neq 0 (echo "ERROR :: conda run runs the wrong python" & exit /b 1)
echo "GOOD :: conda run runs the right python (%PY_VER%), going to force a failure though anyway."
exit /b 1
