# Qore Process Module

This module is a wrapper over the Boost::Process C++ library. It allows Qore to start and manage child processes and process groups, send signals to them and terminate them, and check their memory usage.

## Requirements

- Qore development environment (lib and headers)
- cmake 2.8+
- (optional) Doxygen
- boost >= 1.71: system, filesystem or use -DUSE_INTERNAL_BOOST=1 to use an internal copy of boost submodules

## Build Instructions

Use the so called "out of source" build:

```
mkdir build # in module directory
cd build
cmake -DCMAKE_INSTALL_PREFIX=/path/to/install .. # if there is not -DCMAKE_INSTALL_PREFIX specified, the Qore module dir is used
make -j4
make install
```

Tests are located in `test` directory.

