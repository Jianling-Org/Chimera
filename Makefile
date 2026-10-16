PYTHON ?= python3
CC ?= cc
CMAKE ?= cmake

TEST_BUILD_DIR ?= build/runtime-tests
# Set INSTALL_THIRD_PARTY=1 to bundle third_party (llvm/SVF sources, very
# large) into the wheel/install so `chimera-dev toolchain build` can run without
# a repository checkout. Default: off, the CLI falls back to explicit paths.
THIRD_PARTY_ARGS = $(if $(INSTALL_THIRD_PARTY),--config-settings=cmake.define.CHIMERA_INSTALL_THIRD_PARTY=ON)
WHEEL_TARGET_ARGS = $(if $(TARGET_OS),--target-os "$(TARGET_OS)") \
	$(if $(TARGET_ARCH),--target-arch "$(TARGET_ARCH)") \
	$(if $(TARGET_EXTENSION),--target-extension "$(TARGET_EXTENSION)") \
	$(if $(SCENE),--scene "$(SCENE)")

.PHONY: all test python-test portable-c-test wheel install develop clean

all: wheel

test: python-test portable-c-test

python-test:
	$(PYTHON) tests/run_tests.py

portable-c-test:
	$(CMAKE) -S runtime -B "$(TEST_BUILD_DIR)" \
		-DCMAKE_C_COMPILER="$(CC)" \
		-DCHIMERA_BUILD_RUNTIME=OFF \
		-DCHIMERA_INSTALL_RUNTIME_SOURCE=OFF \
		-DCHIMERA_BUILD_TESTS=ON
	$(CMAKE) --build "$(TEST_BUILD_DIR)" --parallel
	ctest --test-dir "$(TEST_BUILD_DIR)" --output-on-failure

wheel:
	# Source-tree equivalent of `chimera-dev wheel`; keep the release builder
	# usable before this checkout has been installed as a wheel.
	$(PYTHON) tools/build_release_wheel.py --wheel-dir dist $(WHEEL_TARGET_ARGS)

install:
	$(PYTHON) -m pip install . $(THIRD_PARTY_ARGS)

develop:
	$(PYTHON) -m pip install -e . $(THIRD_PARTY_ARGS)

clean:
	rm -rf build/runtime "$(TEST_BUILD_DIR)" build/scikit-build dist
