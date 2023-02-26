# tpm2-pcr experiments

### requires 
- openssl
- tpm2-tss

### compilation
```
cmake -S . -B build
cmake --build build/ --target main && sudo build/main
```