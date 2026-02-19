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

REM Build with Maven, passing brand name as property
call mvn clean package -DskipTests -Dbrand.name=%BRAND_NAME% -Dbrand.version=%BRAND_VERSION%

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Build successful!
    echo Output: target\%BRAND_NAME%-%BRAND_VERSION%-double-click-me.jar
    echo.
) else (
    echo.
    echo Build failed!
    exit /b 1
)
