# PS3 IDA Pro 9.3+ C++ Plugin Source (`ps3ida9`)

High-performance native C++ plugin implementation of `ps3ida9` for IDA Pro 9.3+.

## Building with CMake & IDA SDK

### Out-of-tree build:
```bash
# Point IDASDK to your ida-sdk directory
export IDASDK=/path/to/ida-sdk
cd ps3ida9/cpp
cmake -B build -G Ninja
cmake --build build
```

### In-tree build (inside `ida-sdk`):
Copy or symlink this directory to `ida-sdk/src/plugins/ps3ida9` and build the SDK:
```bash
cd ida-sdk/src
cmake -B build -G Ninja
cmake --build build --target ps3ida9
```

Output binary: `build/plugins/ps3ida9.dll` (or `.so` / `.dylib`). Copy to your IDA Pro `plugins/` directory.
