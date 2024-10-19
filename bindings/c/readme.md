## TidesDB C Bindings

## Compiling to `libtidesdb.so`
```bash
sudo apt-get install g++
g++ -c -fPIC libtidesdb_c.cpp -o libtidesdb_c.o
g++ -shared -o libtidesdb.so libtidesdb_c.o
```