@echo off
setlocal EnableExtensions EnableDelayedExpansion
REM One-shot: build Vortex Internet Android APK into dist\VortexInternetAndroid\
REM Requires JDK 17+ and Android SDK. Set JAVA_HOME / ANDROID_HOME if needed.

cd /d "%~dp0"
set "ROOT=%cd%"
set "APP=%ROOT%\src\android"
set "DIST=%ROOT%\dist\VortexInternetAndroid"
set "OUT_APK=%DIST%\vortex-internet.apk"

echo [BUILD] Vortex Internet Android -^> %OUT_APK%

REM ---- Java ----
if not defined JAVA_HOME (
  if exist "%ProgramFiles%\Android\Android Studio\jbr\bin\java.exe" set "JAVA_HOME=%ProgramFiles%\Android\Android Studio\jbr"
)
if not defined JAVA_HOME (
  for /d %%J in ("%ProgramFiles%\Microsoft\jdk-17*") do (
    if exist "%%~J\bin\java.exe" set "JAVA_HOME=%%~J"
  )
)
if not defined JAVA_HOME (
  for /d %%J in ("%ProgramFiles%\Java\jdk-17*") do (
    if exist "%%~J\bin\java.exe" set "JAVA_HOME=%%~J"
  )
)
if not defined JAVA_HOME (
  echo [!] JAVA_HOME not set and JDK not found. Install JDK 17+ or Android Studio.
  exit /b 1
)
set "PATH=%JAVA_HOME%\bin;%PATH%"
echo [*] JAVA_HOME=%JAVA_HOME%

REM ---- Android SDK ----
if not defined ANDROID_HOME if defined ANDROID_SDK_ROOT set "ANDROID_HOME=%ANDROID_SDK_ROOT%"
if not defined ANDROID_HOME if exist "%LOCALAPPDATA%\Android\Sdk\platform-tools" set "ANDROID_HOME=%LOCALAPPDATA%\Android\Sdk"
if not defined ANDROID_HOME if exist "%USERPROFILE%\AppData\Local\Android\Sdk\platform-tools" set "ANDROID_HOME=%USERPROFILE%\AppData\Local\Android\Sdk"
if not defined ANDROID_HOME (
  echo [!] ANDROID_HOME not set. Install Android SDK / Android Studio, then re-run.
  echo     Example: set ANDROID_HOME=%%LOCALAPPDATA%%\Android\Sdk
  exit /b 1
)
echo [*] ANDROID_HOME=%ANDROID_HOME%

REM local.properties for Gradle (escape backslashes)
set "SDK_DIR=%ANDROID_HOME:\=\\%"
> "%APP%\local.properties" echo sdk.dir=%SDK_DIR%

REM ---- Gradle wrapper ----
if not exist "%APP%\gradle\wrapper" mkdir "%APP%\gradle\wrapper"
if not exist "%APP%\gradle\wrapper\gradle-wrapper.jar" (
  echo [*] downloading gradle-wrapper.jar
  curl.exe -fsSL -o "%APP%\gradle\wrapper\gradle-wrapper.jar" "https://github.com/gradle/gradle/raw/v8.7.0/gradle/wrapper/gradle-wrapper.jar"
  if errorlevel 1 (
    echo [!] Failed to download gradle-wrapper.jar
    exit /b 1
  )
)
if not exist "%APP%\gradlew.bat" (
  echo [*] downloading gradlew.bat
  curl.exe -fsSL -o "%APP%\gradlew.bat" "https://raw.githubusercontent.com/gradle/gradle/v8.7.0/gradlew.bat"
  if errorlevel 1 (
    echo [!] Failed to download gradlew.bat
    exit /b 1
  )
)

REM Sync desktop config into assets when present
if exist "%ROOT%\config\internet.json" (
  copy /Y "%ROOT%\config\internet.json" "%APP%\app\src\main\assets\internet.json" >NUL
  echo [*] assets: internet.json ^<= config\internet.json
)
if exist "%ROOT%\config\multirules.yaml" (
  copy /Y "%ROOT%\config\multirules.yaml" "%APP%\app\src\main\assets\rules.yaml" >NUL
  echo [*] assets: rules.yaml ^<= config\multirules.yaml
)
if not exist "%APP%\app\src\main\assets\geo" mkdir "%APP%\app\src\main\assets\geo"
if exist "%ROOT%\config\geo\geoip-cn.txt" (
  copy /Y "%ROOT%\config\geo\geoip-cn.txt" "%APP%\app\src\main\assets\geo\geoip-cn.txt" >NUL
  echo [*] assets: geo\geoip-cn.txt ^<= config\geo\geoip-cn.txt
)
if exist "%ROOT%\config\geo\geosite-cn.txt" (
  copy /Y "%ROOT%\config\geo\geosite-cn.txt" "%APP%\app\src\main\assets\geo\geosite-cn.txt" >NUL
  echo [*] assets: geo\geosite-cn.txt ^<= config\geo\geosite-cn.txt
)

echo [*] gradle assembleDebug
pushd "%APP%"
call gradlew.bat --no-daemon assembleDebug
set "ERR=!ERRORLEVEL!"
popd
if not "!ERR!"=="0" (
  echo [!] gradle failed
  exit /b !ERR!
)

set "BUILT=%APP%\app\build\outputs\apk\debug\app-debug.apk"
if not exist "%BUILT%" (
  echo [!] APK not found: %BUILT%
  exit /b 1
)

if not exist "%DIST%" mkdir "%DIST%"
if not exist "%DIST%\geo" mkdir "%DIST%\geo"
copy /Y "%BUILT%" "%OUT_APK%" >NUL
copy /Y "%APP%\app\src\main\assets\internet.json" "%DIST%\internet.json" >NUL
copy /Y "%APP%\app\src\main\assets\rules.yaml" "%DIST%\rules.yaml" >NUL
if exist "%APP%\app\src\main\assets\geo\geoip-cn.txt" copy /Y "%APP%\app\src\main\assets\geo\geoip-cn.txt" "%DIST%\geo\geoip-cn.txt" >NUL
if exist "%APP%\app\src\main\assets\geo\geosite-cn.txt" copy /Y "%APP%\app\src\main\assets\geo\geosite-cn.txt" "%DIST%\geo\geosite-cn.txt" >NUL

echo [+] APK  %OUT_APK%
echo [+] Install: adb install -r "%OUT_APK%"
endlocal
exit /b 0
