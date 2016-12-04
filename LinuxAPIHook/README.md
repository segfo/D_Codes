# D Linux API Hook
LinuxでAPI Hookするときに使う。  
アンチアンチデバッグを行うデモ付き。  

# フック用共有ライブラリのビルド方法
```
dub build
```

# フック対象アプリのビルド方法
```
gcc poc/anti-debugging.c -o a.out
```

# gdbでデバッグした状態でフックしてみる
```
$ gdb ./a.out
gdb-peda$ set environment LD_PRELOAD=./D_LinuxAPIHook  
gdb-peda$ run
not debugging.  <=== ptrace(3) return value not -1
run process.
```
