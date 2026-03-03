@echo off
setlocal

REM Builds Toolscreen2 DLL (Release|x64), copies it into EasyInject\custom-dlls,
REM builds EasyInject, then deploys the resulting JAR to MultiMC.

set "MSBUILD_EXE=C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"
set "TOOLSCREEN_SRC=C:\Users\Jojoe\source\repos\Toolscreen2\src"
set "VCXPROJ=%TOOLSCREEN_SRC%\MagnifierDLL.vcxproj"
set "DLL_SRC=%TOOLSCREEN_SRC%\x64\Release\Toolscreen.dll"

set "EASYINJECT_DIR=%~dp0"
set "DLL_DEST_DIR=%EASYINJECT_DIR%custom-dlls"
set "DLL_DEST=%DLL_DEST_DIR%\Toolscreen.dll"

set "JAR_SRC=%EASYINJECT_DIR%target\Toolscreen-1.0.9-double-click-me.jar"
set "JAR_DEST_DIR=J:\MultiMC\instances\zWallMod"
set "JAR_DEST=%JAR_DEST_DIR%\Toolscreen.jar"
set "JAR_FALLBACK=%JAR_DEST_DIR%\Toolscreen-new.jar"

echo ============================================
echo   Toolscreen2 DLL -^> EasyInject -^> Deploy
echo ============================================
echo.

if not exist "%MSBUILD_EXE%" (
  echo ERROR: MSBuild not found:
  echo   %MSBUILD_EXE%
  exit /b 1
)

if not exist "%VCXPROJ%" (
  echo ERROR: vcxproj not found:
  echo   %VCXPROJ%
  exit /b 1
)

echo [1/4] Building DLL (Release ^| x64)...
"%MSBUILD_EXE%" "%VCXPROJ%" /m /t:Build /p:Configuration=Release /p:Platform=x64
if errorlevel 1 (
  echo.
  echo ERROR: DLL build failed.
  exit /b 1
)

if not exist "%DLL_SRC%" (
  echo.
  echo ERROR: Expected DLL output not found:
  echo   %DLL_SRC%
  exit /b 1
)

echo.
echo [2/4] Copying DLL into EasyInject custom-dlls...
if not exist "%DLL_DEST_DIR%" mkdir "%DLL_DEST_DIR%" >nul 2>nul
copy /Y "%DLL_SRC%" "%DLL_DEST%" >nul
if errorlevel 1 (
  echo.
  echo ERROR: Failed to copy DLL to:
  echo   %DLL_DEST%
  exit /b 1
)

echo.
echo [3/4] Running EasyInject build.bat...
call "%EASYINJECT_DIR%build.bat"
if errorlevel 1 (
  echo.
  echo ERROR: EasyInject build failed.
  exit /b 1
)

if not exist "%JAR_SRC%" (
  echo.
  echo ERROR: Expected JAR output not found:
  echo   %JAR_SRC%
  exit /b 1
)

if not exist "%JAR_DEST_DIR%" (
  echo.
  echo ERROR: MultiMC instance folder not found:
  echo   %JAR_DEST_DIR%
  exit /b 1
)

echo.
echo [4/4] Deploying JAR...
copy /Y "%JAR_SRC%" "%JAR_DEST%" >nul 2>nul
if errorlevel 1 (
  echo NOTE: %JAR_DEST% appears locked; copying to Toolscreen-new.jar instead...
  copy /Y "%JAR_SRC%" "%JAR_FALLBACK%" >nul
  if errorlevel 1 (
    echo.
    echo ERROR: Failed to copy JAR to:
    echo   %JAR_FALLBACK%
    exit /b 1
  )
  echo Copied to:
  echo   %JAR_FALLBACK%
) else (
  echo Copied to:
  echo   %JAR_DEST%
)

echo.
echo Done.
exit /b 0
