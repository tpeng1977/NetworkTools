# Cross-platform Makefile for Linux, macOS, and Windows (MinGW/MSYS).
# Prefer: make
# Or:     ./build.sh   /   build.bat   /   cmake -B build && cmake --build build

# Default compiler: clang++ on macOS, g++ elsewhere (override with CXX=...).
UNAME_S := $(shell uname -s 2>/dev/null || echo Unknown)
ifeq ($(origin CXX),default)
  ifeq ($(UNAME_S),Darwin)
    CXX := clang++
  else
    CXX := g++
  endif
endif

CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Iinclude
LDFLAGS  ?=

ifeq ($(OS),Windows_NT)
  LDFLAGS += -lws2_32
  EXE := .exe
  RM := del /Q
  NULL := NUL
else
  LDFLAGS += -pthread
  EXE :=
  RM := rm -f
  NULL := /dev/null
endif

.PHONY: all clean test help

all: server$(EXE) client$(EXE) smartlink$(EXE) multilink$(EXE) local$(EXE) peer$(EXE)
ifeq ($(OS),Windows_NT)
all: ap2socks5.exe activate_net.exe enable_net.exe
endif

help:
	@echo "Targets: all, test, clean"
	@echo "CXX=$(CXX)  OS=$(OS)  UNAME=$(UNAME_S)"

server$(EXE): src/server.cpp include/config.hpp include/net.hpp include/protocol.hpp include/vortex_cipher.hpp
	$(CXX) $(CXXFLAGS) src/server.cpp -o $@ $(LDFLAGS)

client$(EXE): src/client.cpp include/config.hpp include/net.hpp include/protocol.hpp include/vortex_cipher.hpp
	$(CXX) $(CXXFLAGS) src/client.cpp -o $@ $(LDFLAGS)

smartlink$(EXE): src/smartlink.cpp include/config.hpp include/net.hpp include/protocol.hpp include/vortex_cipher.hpp include/rules.hpp
	$(CXX) $(CXXFLAGS) src/smartlink.cpp -o $@ $(LDFLAGS) $(if $(filter Windows_NT,$(OS)),-liphlpapi,)

multilink$(EXE): src/multilink.cpp include/config.hpp include/net.hpp include/protocol.hpp include/vortex_cipher.hpp include/rules.hpp
	$(CXX) $(CXXFLAGS) src/multilink.cpp -o $@ $(LDFLAGS) $(if $(filter Windows_NT,$(OS)),-liphlpapi,)

local$(EXE): src/local.cpp include/config.hpp include/net.hpp include/protocol.hpp
	$(CXX) $(CXXFLAGS) src/local.cpp -o $@ $(LDFLAGS)

peer$(EXE): src/peer.cpp include/config.hpp include/net.hpp include/protocol.hpp include/vortex_cipher.hpp
	$(CXX) $(CXXFLAGS) src/peer.cpp -o $@ $(LDFLAGS)

ifeq ($(OS),Windows_NT)
ap2socks5.exe: src/ap2socks5.cpp include/packet_build.hpp include/config.hpp
	$(CXX) $(CXXFLAGS) src/ap2socks5.cpp -o $@ $(LDFLAGS) -liphlpapi

activate_net.exe: src/activate_net.cpp include/packet_build.hpp include/config.hpp include/net.hpp
	$(CXX) $(CXXFLAGS) src/activate_net.cpp -o $@ $(LDFLAGS) -liphlpapi

enable_net.exe: src/enable_net.cpp include/packet_build.hpp include/config.hpp include/net.hpp
	$(CXX) $(CXXFLAGS) src/enable_net.cpp -o $@ $(LDFLAGS) -liphlpapi
endif

tests/test_core$(EXE): tests/test_core.cpp include/*.hpp
	$(CXX) $(CXXFLAGS) tests/test_core.cpp -o $@ $(LDFLAGS)

tests/test_rules$(EXE): tests/test_rules.cpp include/rules.hpp
	$(CXX) $(CXXFLAGS) tests/test_rules.cpp -o $@ $(LDFLAGS)

tests/test_multilink$(EXE): tests/test_multilink.cpp include/config.hpp include/rules.hpp
	$(CXX) $(CXXFLAGS) tests/test_multilink.cpp -o $@ $(LDFLAGS)

test: tests/test_core$(EXE) tests/test_rules$(EXE) tests/test_multilink$(EXE) all
	./tests/test_core$(EXE)
	./tests/test_rules$(EXE)
	./tests/test_multilink$(EXE)

clean:
ifeq ($(OS),Windows_NT)
	-@$(RM) server.exe client.exe smartlink.exe multilink.exe local.exe peer.exe ap2socks5.exe activate_net.exe enable_net.exe tests\test_core.exe tests\test_rules.exe tests\test_multilink.exe 2>$(NULL)
else
	$(RM) server client smartlink multilink local peer tests/test_core tests/test_rules tests/test_multilink
	$(RM) tests/echo_server tests/socks5_http_get tests/probe_test
	$(RM) tests/wrong_secret_test tests/binary_echo_test tests/stress_test
endif
