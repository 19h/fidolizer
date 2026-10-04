# Fidolizer build wrapper. CMake does the real work.
#
#   make                build the release binary and tests
#   make test           build and run the CTAP test suite
#   make install        install into PREFIX (default /usr/local)
#   make uninstall
#   make clean          remove build products, keep the CMake cache
#   make distclean      delete the build directory
#   make run            serve the authenticator from the build tree

PREFIX ?= /usr/local
BUILD_DIR ?= build
BUILD_TYPE ?= Release
CMAKE ?= cmake
CXX ?= clang++
JOBS ?=

CMAKE_FLAGS := -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) -DCMAKE_INSTALL_PREFIX=$(PREFIX) -DCMAKE_CXX_COMPILER=$(CXX)

.PHONY: all configure build test install uninstall clean distclean run help

all: build

help:
	@echo "targets: build test install uninstall clean distclean run"
	@echo "variables: PREFIX=$(PREFIX) BUILD_DIR=$(BUILD_DIR) BUILD_TYPE=$(BUILD_TYPE) CXX=$(CXX)"

configure:
	$(CMAKE) -S . -B $(BUILD_DIR) $(CMAKE_FLAGS)

build: configure
	$(CMAKE) --build $(BUILD_DIR) --parallel $(JOBS)

test: build
	$(CMAKE) -E env CTEST_OUTPUT_ON_FAILURE=1 $(CMAKE) --build $(BUILD_DIR) --target fidolizer_tests
	cd $(BUILD_DIR) && ctest --output-on-failure
	node extension/origin-select.test.js

install: build
	$(CMAKE) --install $(BUILD_DIR)

uninstall: configure
	$(CMAKE) --build $(BUILD_DIR) --target uninstall

clean:
	@if [ -d $(BUILD_DIR) ]; then $(CMAKE) --build $(BUILD_DIR) --target clean; fi

distclean:
	rm -rf $(BUILD_DIR)

run: build
	$(BUILD_DIR)/fidolizer serve
