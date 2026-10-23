@echo off
REM Build Vortex Shield on Windows (MinGW g++ / MSYS2).
setlocal EnableExtensions

set "ROOT=%~dp0"
cd /d "%ROOT%"

if not defined CXX set "CXX=g++"
set "CXXFLAGS=-std=c++17 -O2 -Wall -Wextra -Iinclude"
set "LDFLAGS=-lws2_32"

where %CXX% >NUL 2>&1
if errorlevel 1 (
  echo ERROR: compiler "%CXX%" not found. Install MinGW-w64 or MSYS2 and add g++ to PATH.
  exit /b 1
)

echo [BUILD] platform=Windows compiler=%CXX%
echo [BUILD] server...
%CXX% %CXXFLAGS% src\server.cpp -o server.exe %LDFLAGS%
if errorlevel 1 exit /b 1

echo [BUILD] client...
%CXX% %CXXFLAGS% src\client.cpp -o client.exe %LDFLAGS%
if errorlevel 1 exit /b 1

echo [BUILD] smartlink...
%CXX% %CXXFLAGS% src\smartlink.cpp -o smartlink.exe %LDFLAGS% -liphlpapi
if errorlevel 1 exit /b 1

echo [BUILD] multilink...
%CXX% %CXXFLAGS% src\multilink.cpp -o multilink.exe %LDFLAGS% -liphlpapi
if errorlevel 1 exit /b 1

echo [BUILD] local...
%CXX% %CXXFLAGS% src\local.cpp -o local.exe %LDFLAGS%
if errorlevel 1 exit /b 1

echo [BUILD] peer...
%CXX% %CXXFLAGS% src\peer.cpp -o peer.exe %LDFLAGS%
if errorlevel 1 exit /b 1

echo [BUILD] ap2socks5...
set "APRES="
where windres >NUL 2>&1
if not errorlevel 1 (
  windres -I src src\ap2socks5.rc -O coff -o src\ap2socks5.res
  if not errorlevel 1 set "APRES=src\ap2socks5.res"
)
%CXX% %CXXFLAGS% src\ap2socks5.cpp %APRES% -o ap2socks5.exe %LDFLAGS% -liphlpapi
if errorlevel 1 exit /b 1

echo [BUILD] activate_net...
set "ANRES="
where windres >NUL 2>&1
if not errorlevel 1 (
  windres -I src src\activate_net.rc -O coff -o src\activate_net.res
  if not errorlevel 1 set "ANRES=src\activate_net.res"
)
%CXX% %CXXFLAGS% src\activate_net.cpp %ANRES% -o activate_net.exe %LDFLAGS% -liphlpapi
if errorlevel 1 exit /b 1

echo [BUILD] enable_net...
set "ENRES="
where windres >NUL 2>&1
if not errorlevel 1 (
  windres -I src src\enable_net.rc -O coff -o src\enable_net.res
  if not errorlevel 1 set "ENRES=src\enable_net.res"
)
%CXX% %CXXFLAGS% src\enable_net.cpp %ENRES% -o enable_net.exe %LDFLAGS% -liphlpapi
if errorlevel 1 exit /b 1

echo [BUILD] internet...
set "INRES="
where windres >NUL 2>&1
if not errorlevel 1 (
  windres -I src src\internet.rc -O coff -o src\internet.res
  if not errorlevel 1 set "INRES=src\internet.res"
)
%CXX% %CXXFLAGS% src\internet.cpp %INRES% -o internet.exe %LDFLAGS% -liphlpapi
if errorlevel 1 exit /b 1

if /I "%~1"=="test" goto build_test
if /I "%~1"=="all" goto build_all
goto done

:build_all
echo [BUILD] integration helpers...
%CXX% %CXXFLAGS% tests\echo_server.cpp -o tests\echo_server.exe %LDFLAGS%
if errorlevel 1 exit /b 1
%CXX% %CXXFLAGS% tests\socks5_http_get.cpp -o tests\socks5_http_get.exe %LDFLAGS%
if errorlevel 1 exit /b 1
%CXX% %CXXFLAGS% tests\probe_test.cpp -o tests\probe_test.exe %LDFLAGS%
if errorlevel 1 exit /b 1
%CXX% %CXXFLAGS% tests\wrong_secret_test.cpp -o tests\wrong_secret_test.exe %LDFLAGS%
if errorlevel 1 exit /b 1
%CXX% %CXXFLAGS% tests\binary_echo_test.cpp -o tests\binary_echo_test.exe %LDFLAGS%
if errorlevel 1 exit /b 1
%CXX% %CXXFLAGS% tests\stress_test.cpp -o tests\stress_test.exe %LDFLAGS%
if errorlevel 1 exit /b 1

:build_test
echo [BUILD] unit test...
%CXX% %CXXFLAGS% tests\test_core.cpp -o tests\test_core.exe %LDFLAGS%
if errorlevel 1 exit /b 1
%CXX% %CXXFLAGS% tests\test_packet_build.cpp -o tests\test_packet_build.exe
if errorlevel 1 exit /b 1
%CXX% %CXXFLAGS% tests\test_rules.cpp -o tests\test_rules.exe %LDFLAGS%
if errorlevel 1 exit /b 1
%CXX% %CXXFLAGS% tests\test_multilink.cpp -o tests\test_multilink.exe %LDFLAGS%
if errorlevel 1 exit /b 1
%CXX% %CXXFLAGS% tests\test_multirules.cpp -o tests\test_multirules.exe %LDFLAGS% -liphlpapi
if errorlevel 1 exit /b 1
%CXX% %CXXFLAGS% tests\test_peer_protocol.cpp -o tests\test_peer_protocol.exe %LDFLAGS%
if errorlevel 1 exit /b 1
echo [TEST] running unit tests...
tests\test_core.exe
if errorlevel 1 exit /b 1
tests\test_packet_build.exe
if errorlevel 1 exit /b 1
tests\test_rules.exe
if errorlevel 1 exit /b 1
tests\test_multilink.exe
if errorlevel 1 exit /b 1
tests\test_multirules.exe
if errorlevel 1 exit /b 1
tests\test_peer_protocol.exe
if errorlevel 1 exit /b 1

:done
echo [BUILD] OK
echo   server.exe config\server.json
echo   client.exe config\client.json
echo   smartlink.exe config\smartlink.json
echo   multilink.exe config\multilink.json
echo   local.exe config\local.json
echo   peer.exe config\peer.json
echo   ap2socks5.exe config\ap2socks5.json
echo   activate_net.exe config\multilink.json
echo   enable_net.exe config\enable_net.json
echo   internet.exe config\internet.json
endlocal
