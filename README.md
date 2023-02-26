# tpm2-pcr experiments

### requires 
- openssl
- tpm2-tss

### compilation
```
cmake -S . -B build
cmake --build build/ --target main && sudo build/main
```

### tss2 documentation
see https://tpm2-tss.readthedocs.io/en/latest/group__esys.html