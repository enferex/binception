## binception: Generate hash values for functions within a binary.

### What
binception is a utility that locates functions within an elf file (library,
executable, object).  The hash values for all discovered functions can
be reported to stdout or saved in a sqlite3 database.

### Why
binception is used to hash the code of functions within an ELF binary.  The goal
is to use this tool to figure out if that same function exists within another
binary.  This can be useful for detecting libraries used to create a
particular statically (and stripped) executable.

### Uses
* Create a database of (use -d option) of libraries and determine which libraries are used in a static elf file.
* Once a database has been generated, use that database along with the -s option
to find what libraries have functions that match the functions in the object
file of question.

The following use case shows how this tool can be used to determine which
libraries compose another program.  Results will be saved in a database called
'mylibs.sql'

1. Generate the database of library data to search (this is not recursive so
perhaps a use of your shell's ```for``` builtin would be more appropriate):

    ./binception -d mylibs.sql /lib64/*

1. Now scan a file (perhaps statically linked and stripped) to see what libraries compose it: 

    ./binception -d mylibs.sql -s myexec

### Dependencies
* binutils: https://www.gnu.org/software/binutils/ (ELF handling)
* sqlite3: https://www.sqlite.org/  (Database functionality)
* openssl: https://www.openssl.org/ (MD5 hashing algo)

### Building
Run *make* from the source directory.  The resulting binary can be copied
anywhere.

### Contact
mattdavis9@gmail.com (enferex)
