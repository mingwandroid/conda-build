rmdir /s /q C:\test-conda-run-in-recipe-py38-noact
rmdir /s /q C:\test-conda-run-in-recipe-py37-noact

call conda deactivate
pushd %~dp0..\..
  mkdir C:\test-conda-run-in-recipe-py38-noact
  conda build lief-feedstock -c defaults --python=3.8 --croot C:\test-conda-run-in-recipe-py38-noact --no-build-id 2>&1 | C:\msys32\usr\bin\tee.exe C:\test-conda-run-in-recipe-py38-noact\build.log
  mkdir C:\test-conda-run-in-recipe-py37-noact
  conda build lief-feedstock -c defaults --python=3.8 --croot C:\test-conda-run-in-recipe-py37-noact --no-build-id 2>&1 | C:\msys32\usr\bin\tee.exe C:\test-conda-run-in-recipe-py37-noact\build.log
popd

:: activation stacking seems busted.
:: call "C:\opt\conda\Scripts\..\condabin\conda_hook.bat"
:: call "C:\opt\conda\Scripts\..\condabin\conda.bat" activate
:: call "C:\opt\conda\Scripts\..\condabin\conda.bat" activate "C:\lief-build-2-py38-noact\_h_env"
:: call "C:\opt\conda\Scripts\..\condabin\conda.bat" activate --stack "C:\lief-build-2-py38-noact\_build_env"
:: echo %PATH%
:: 
:: conda activate 
