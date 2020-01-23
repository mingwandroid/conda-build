@echo ON
setlocal enabledelayedexpansion

set CONDA_TEST_SAVE_TEMPS=1
echo "(install-py-lief.bat) PATH just before conda run -p %RECIPE_DIR%\echo_path.bat is %PATH%"
where conda
call conda run -p %PREFIX% --debug-wrapper-scripts call %RECIPE_DIR%\echo_path.bat
echo "(install-py-lief.bat) Done call conda run -p"
if %errorlevel% neq 0 exit /b 1

:: The commented out tests above are overkill, but we should run this one at least.
call conda run -p %PREFIX% --debug-wrapper-scripts python -v --version | findstr /r /c:%PY_VER%
if %errorlevel% neq 0 (echo "ERROR :: conda run runs the wrong python" & exit /b 1)

exit /b 0
