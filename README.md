# HYBRID PKI VIA RSA-4096 AND GGH LATTICE SIGNATURES FOR SCADA

This team repository separates cryptography (`crypto/`), future PKI/X.509 work (`pki/`), and future SCADA-security work (`scada/`). Person 1 owns the implemented cryptography module only: RSA-4096 with RSA-PSS/SHA-256, an educational GGH hash-and-sign reference implementation, hybrid signing, tests, benchmarks, and the GUI.

The GGH component follows the original GGH hash-and-sign construction: hash a canonical message to a lattice target, use the private short basis for Babai round-off, and verify public-lattice membership plus distance. It is educational and historically insecure; it is not a standardized or production post-quantum signature scheme.

## Build and test

On Windows, prefer the reproducible scripts (detect/install CMake, modern MinGW-w64, and OpenSSL via winget):

```powershell
.\setup.ps1
.\run.ps1
```

Manual configure/build remains available:

```powershell
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=C:/mingw64/bin/g++.exe -DCMAKE_MAKE_PROGRAM=C:/mingw64/bin/mingw32-make.exe -DOPENSSL_ROOT_DIR="C:/Program Files/OpenSSL-Win64"
cmake --build build
ctest --test-dir build --output-on-failure
```

Legacy MinGW.org GCC 6.3 is not supported. Use a modern MinGW-w64 toolchain installed to a path without spaces (this project's scripts use `C:\mingw64`).

## GUI demonstration

Run `build/hybrid_crypto_gui.exe`. Generate both keys, enter a command, sign, verify, and use the tampering controls. RSA/GGH results, signature sizes, event log entries, and timings are produced by the live backend. Private keys are never displayed or persisted.
