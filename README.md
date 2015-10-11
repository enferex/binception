## efh: ELF Func Hash: Generates hash values for all functions in a binary.

### What
efh is a utility that locates functions within an elf file (library, executable,
object).  The hash values for all discovered functions can be reported to stdout
or saved in a sqlite3 database.

### Dependencies
sqlite3: https://www.sqlite.org/  (Provides database functionality)
openssl: https://www.openssl.org/ (Provides MD5 hashing algo)

### Building
Run *make* from the source directory.  The resulting binary can be copied
anywhere.

### Contact
mattdavis9@gmail.com (enferex)
