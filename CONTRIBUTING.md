### When contributing to TidesDB a couple things.

- Make sure your code comments are all lower case and in English and using `/* */` style.
- Make sure if your method is not returning anything or you don't care for the return to use `void` as the return type. or `(void)some_func()`
- When adding to tidesdb.c or tidesdb.h please make sure you follow prefixing conventions for internal, public methods.
- Use `code_formatter.sh` to format source code before submitting a pull request.
- Assure your changes are tested and pass all tests.
- Make sure your changes are well documented.