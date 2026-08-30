@echo off
setlocal

REM Builds x64 and ARM64 Toolscreen payloads, stages them for a universal
REM EasyInject package, builds EasyInject, then deploys the resulting JAR.

set "EASYINJECT_DIR=%~dp0"
set "TOOLSCREEN_DIR=%EASYINJECT_DIR%..\Toolscreen2"
set "X64_BUILD_DIR=%TOOLSCREEN_DIR%\out\easyinject-payload-x64"
set "ARM64_BUILD_DIR=%TOOLSCREEN_DIR%\out\easyinject-payload-arm64"
set "X64_DLL_SRC=%X64_BUILD_DIR%\bin\Release\Toolscreen.dll"
set "ARM64_DLL_SRC=%ARM64_BUILD_DIR%\bin\Release\Toolscreen.dll"
set "X64_LOGGER_SRC=%X64_BUILD_DIR%\bin\Release\liblogger_x64.dll"
set "ARM64_LOGGER_SRC=%ARM64_BUILD_DIR%\bin\Release\liblogger_arm64.dll"
set "DLL_DEST_DIR=%EASYINJECT_DIR%custom-dlls"
set "LOGGER_DEST_DIR=%EASYINJECT_DIR%src\main\resources\dlls"

set "BRAND_NAME=EasyInjectBundled"
set "BRAND_VERSION=1.0"
for /f "tokens=1,* delims==" %%a in ('findstr /b "brand.name=" "%EASYINJECT_DIR%branding.properties" 2^>nul') do set "BRAND_NAME=%%b"
for /f "tokens=1,* delims==" %%a in ('findstr /b "brand.version=" "%EASYINJECT_DIR%branding.properties" 2^>nul') do set "BRAND_VERSION=%%b"
set "JAR_SRC=%EASYINJECT_DIR%target\%BRAND_NAME%-%BRAND_VERSION%-double-click-me.jar"
set "JAR_DEST_DIR=J:\MultiMC\instances\zWallMod"
set "JAR_DEST=%JAR_DEST_DIR%\Toolscreen.jar"
set "JAR_FALLBACK=%JAR_DEST_DIR%\Toolscreen-new.jar"

echo ============================================
echo   Toolscreen2 DLL -^> EasyInject -^> Deploy
echo ============================================
echo.

where cmake >nul 2>nul
if errorlevel 1 (
  echo ERROR: CMake was not found on PATH.
  exit /b 1
)

if not exist "%TOOLSCREEN_DIR%\CMakeLists.txt" (
  echo ERROR: Toolscreen2 repository not found:
  echo   %TOOLSCREEN_DIR%
  exit /b 1
)

echo [1/6] Configuring Toolscreen payload builds...
cmake -S "%TOOLSCREEN_DIR%" -B "%X64_BUILD_DIR%" -A x64 -DTOOLSCREEN_ENABLE_JAR_PACKAGING=OFF -DTOOLSCREEN_ENABLE_EXE_PACKAGING=OFF -DTOOLSCREEN_BUILD_LIBLOGGER_FROM_SOURCE=ON
if errorlevel 1 (
  echo ERROR: x64 Toolscreen configure failed.
  exit /b 1
)
cmake -S "%TOOLSCREEN_DIR%" -B "%ARM64_BUILD_DIR%" -A ARM64 -DTOOLSCREEN_TARGET_ARCH=arm64 -DTOOLSCREEN_ENABLE_JAR_PACKAGING=OFF -DTOOLSCREEN_ENABLE_EXE_PACKAGING=OFF -DTOOLSCREEN_BUILD_LIBLOGGER_FROM_SOURCE=ON
if errorlevel 1 (
  echo ERROR: ARM64 Toolscreen configure failed.
  exit /b 1
)

echo [2/6] Building x64 Toolscreen and liblogger...
cmake --build "%X64_BUILD_DIR%" --config Release --parallel --target Toolscreen liblogger_windows
if errorlevel 1 (
  echo ERROR: x64 payload build failed.
  exit /b 1
)

echo [3/6] Building ARM64 Toolscreen and liblogger...
cmake --build "%ARM64_BUILD_DIR%" --config Release --parallel --target Toolscreen liblogger_windows
if errorlevel 1 (
  echo ERROR: ARM64 payload build failed.
  exit /b 1
)

for %%f in ("%X64_DLL_SRC%" "%ARM64_DLL_SRC%" "%X64_LOGGER_SRC%" "%ARM64_LOGGER_SRC%") do (
  if not exist "%%~f" (
    echo ERROR: Expected payload output not found: %%~f
    exit /b 1
  )
)

echo [4/6] Staging universal payloads...
if not exist "%DLL_DEST_DIR%" mkdir "%DLL_DEST_DIR%" >nul 2>nul
if not exist "%LOGGER_DEST_DIR%" mkdir "%LOGGER_DEST_DIR%" >nul 2>nul
if exist "%DLL_DEST_DIR%\Toolscreen.dll" del /Q "%DLL_DEST_DIR%\Toolscreen.dll"
copy /Y "%X64_DLL_SRC%" "%DLL_DEST_DIR%\Toolscreen_x64.dll" >nul
if errorlevel 1 goto :stage_failed
copy /Y "%ARM64_DLL_SRC%" "%DLL_DEST_DIR%\Toolscreen_arm64.dll" >nul
if errorlevel 1 goto :stage_failed
copy /Y "%X64_LOGGER_SRC%" "%LOGGER_DEST_DIR%\liblogger_x64.dll" >nul
if errorlevel 1 goto :stage_failed
copy /Y "%ARM64_LOGGER_SRC%" "%LOGGER_DEST_DIR%\liblogger_arm64.dll" >nul
if errorlevel 1 goto :stage_failed

echo [5/6] Running EasyInject build.bat...
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
echo [6/6] Deploying JAR...
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

:stage_failed
echo ERROR: Failed to stage universal payloads.
exit /b 1
