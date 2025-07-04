A simple benchmark for hardening options which runs Clang on huge slow files.

1) Clone LLVM and checkout llvmorg-20.1.7 tag.

TODO: prepare sources in `run.sh` ?

2) Build once with `-DCMAKE_CXX_COMPILER=clang` and generate .ii files for
   CGBuiltins, X86ISelLowering and PassBuilder and put them to `files/` subdir.

TODO: generate .ii files in `run.sh`

3) Finally run
```
$ ./run.sh configs.txt
```
