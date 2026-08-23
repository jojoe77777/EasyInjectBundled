@echo off
REM EasyInjectBundled Build Script
REM 
REM Usage:
REM   1. Edit branding.properties to set your project name
REM   2. Place your DLL files in the custom-dlls folder
REM   3. Run this script
REM   4. Find your branded JAR in target/
REM

echo Building EasyInjectBundled...
echo.

cd /d "%~dp0"

REM Read branding from properties file
set BRAND_NAME=EasyInjectBundled
set BRAND_VERSION=1.0

for /f "tokens=1,* delims==" %%a in ('findstr /b "brand.name=" branding.properties 2^>nul') do set BRAND_NAME=%%b
for /f "tokens=1,* delims==" %%a in ('findstr /b "brand.version=" branding.properties 2^>nul') do set BRAND_VERSION=%%b

echo ============================================
echo   Project:  %BRAND_NAME%
echo   Version:  %BRAND_VERSION%
echo ============================================
echo.

REM Check if custom-dlls folder exists
if not exist "custom-dlls" (
    echo Creating custom-dlls folder...
    mkdir custom-dlls
)

REM List DLLs that will be bundled
echo DLLs to be bundled:
echo   - liblogger_x64.dll (built-in)
for %%f in (custom-dlls\*.dll) do (
    echo   - %%~nxf
)
echo.

REM Build both installer JAR variants and the existing downloader JAR.
call mvn clean package -Dbrand.name=%BRAND_NAME% -Dbrand.version=%BRAND_VERSION%

if %ERRORLEVEL% NEQ 0 goto :build_failed

REM Build both native installer variants from the same source.
call cmake -S exe -B exe\build -A x64
if %ERRORLEVEL% NEQ 0 goto :build_failed
call cmake --build exe\build --config Release --parallel
if %ERRORLEVEL% NEQ 0 goto :build_failed

REM Preserve the existing native downloader build.
call cmake -S toolscreen-installer-exe -B toolscreen-installer-exe\build -A x64
if %ERRORLEVEL% NEQ 0 goto :build_failed
call cmake --build toolscreen-installer-exe\build --config Release --parallel
if %ERRORLEVEL% NEQ 0 goto :build_failed

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Build successful!
    echo Output: target\%BRAND_NAME%-%BRAND_VERSION%-double-click-me.jar
    echo Output: target\%BRAND_NAME%-%BRAND_VERSION%-double-click-me-reduced-av-heuristics.jar
    echo Output: target\toolscreen-downloader.jar
    echo Output: exe\build\Release\%BRAND_NAME%-%BRAND_VERSION%-double-click-me.exe
    echo Output: exe\build\Release\%BRAND_NAME%-%BRAND_VERSION%-double-click-me-reduced-av-heuristics.exe
    echo Output: toolscreen-installer-exe\build\Release\toolscreen-downloader.exe
    echo.
) else (
    goto :build_failed
)
exit /b 0

:build_failed
echo.
echo Build failed!
exit /b 1
