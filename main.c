#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#define PACKAGE         42  /* Defined to ignore config.h include in bfd.h */
#define PACKAGE_VERSION 42  /* Defined to ignore config.h include in bfd.h */
#include <bfd.h>
#include <dis-asm.h>
#ifdef USE_OPENSSL
#include <openssl/md5.h>
#endif
#ifdef USE_SQLITE
#include <sqlite3.h>
#endif


/* Special thanks to the following for providing a very helpful example of how
 * to use libopcodes + libbfd:
 * http://www.toothycat.net/wiki/wiki.pl?Binutils/libopcodes
 */
#define _PR(_tag, ...) do {                            \
        fprintf(stderr, "[binema]" _tag __VA_ARGS__); \
        fputc('\n', stderr);                           \
} while(0)

#define ERR(...) do {             \
    _PR("[error] ", __VA_ARGS__); \
    exit(EXIT_FAILURE);           \
} while(0)

#ifdef DEBUG
#define DBG(...) _PR("[debug] ", __VA_ARGS__)
#else
#define DBG(...)
#endif


/* Type representing the start/end of a function's code (.text section) */
typedef struct _func_t 
{
    bfd_vma st; /* Address where a function begins (.text) */
    bfd_vma en; /* Address where a function ends (.text)   */
#ifdef USE_OPENSSL
    unsigned char hash[MD5_DIGEST_LENGTH];
#else
    unsigned char hash[1];
#endif
    struct _func_t *next;
} func_t;
static func_t *all_funcs;


/* Globals accessable from callbacks which have no other means of accessing this
 * data.
 */
static bfd *bin;
static asection *text;
static struct disassemble_info dis_info;


/* Address to the current instruction we are processing */
static bfd_vma curr_addr, start_addr;


static void usage(const char *execname)
{
    printf("Usage: %s [executable] [-h]\n", execname);
    exit(EXIT_SUCCESS);
}


/* Add a function to our list of functions */
static void add_node(func_t *fn)
{
    fn->next = all_funcs;
    all_funcs = fn;
}


static func_t *new_func(bfd_vma st, bfd_vma en, bfd *bfd, asection *text)
{
    func_t *fn = calloc(1, sizeof(func_t));

    if (!fn)
    {
        fprintf(stderr, "Not enough memory to allocate a node\n");
        exit(errno);
    }

    fn->st = st;
    fn->en = en;
#ifdef USE_OPENSSL
    {
        unsigned char *data;
        const file_ptr off = text->filepos + (st - start_addr);
        if (!(data = malloc(en - st)))
        {
            printf("Not enough memory to allocate function data\n");
            exit(errno);
        }
        bfd_get_section_contents(bfd, text, data, off, en - st);
        MD5(data, en - st, fn->hash);
    }
#endif
    return fn;
}


/* Reclaim memory from a list of func information */
static void destroy_funcs(func_t **fnp)
{
    func_t *next, *fn = *fnp;

    while (fn)
    {
        next = fn->next;
        free(fn);
        fn = next;
    }

    *fnp = NULL;
}


/* Each insn and all arguments are passed as individual strings:
 * We only care about calls and returns.
 *
 * We look for call and the next value, which should be the address/function
 * being called.
 *
 * We also look for 'ret' and the next address will be the beginning of the new
 * function.
 */
static int process_insn(void *stream, const char *fmt, ...)
{
    va_list va;
    const char *str;
    static bfd_vma st;

    va_start(va, fmt);
    str = va_arg(va, char *);

    if (!str)
    {
        va_end(va);
        return 0;
    }

    /* If return, compute hash from start to ret */
    if (!st)
      st = curr_addr;
    else if (strncmp(str, "ret", strlen("ret")) == 0)
    {
        func_t *fn = new_func(st, curr_addr, bin, text);
        add_node(fn);
        st = 0;
    }

    va_end(va);
    return 0;
}


/* Open the file and use libopcodes + libfd to create a list 
 * of function hashes.
 */
static void *build_function_hash_list(const char *fname)
{
    int length;
    disassembler_ftype dis;

    /* Initialize the binary description (needed for disassembly parsing) */
    bfd_init();
    if (!(bin = bfd_openr(fname, NULL)))
    {
        bfd_perror("Error opening executable");
        exit(EXIT_FAILURE);
    }

    if (!bfd_check_format(bin, bfd_object))
    {
        bfd_perror("Bad format (expected object)");
        exit(EXIT_FAILURE);
    }

    /* Get the information about the .text section of the binary */
    if (!(text = bfd_get_section_by_name(bin, ".text")))
    {
        bfd_perror("Could not locate .text section of the binary");
        exit(EXIT_FAILURE);
    }

    /* Initialize libopcodes */
    init_disassemble_info(&dis_info, stdout, (fprintf_ftype)process_insn);
    dis_info.arch = bfd_get_arch(bin);
    dis_info.mach = bfd_get_mach(bin);
    dis_info.section = text;
    dis_info.buffer_vma = text->vma;
    dis_info.buffer_length = text->size;
    disassemble_init_for_target(&dis_info);

    /* Suck in .text */
    bfd_malloc_and_get_section(bin, text, &dis_info.buffer);

    /* Create a handle to the disassembler */
    if (!(dis = disassembler(bin)))
    {
        bfd_perror("Error creating disassembler parser");
        exit(EXIT_FAILURE);
    }

    /* Start disassembly... */
    curr_addr = start_addr = bfd_get_start_address(bin);
    while ((length = dis(curr_addr, &dis_info)))
    {
        curr_addr += length;
        if ((length < 1) || (curr_addr >= (text->size + start_addr)))
            break;
    }

    return NULL;
}


static void dump_funcs(const func_t *fns)
{
    int i, j;
    const func_t *fn;

    for (fn=fns; fn; fn=fn->next)
    {
        bfd_vma dist = fn->en - fn->st;
        printf("%-2.d) %p -- %p (%-4.llu bytes)", ++i, fn->st, fn->en, dist);
#ifdef USE_OPENSSL
        printf(" 0x");
        for (j=0; j<MD5_DIGEST_LENGTH; ++j)
          printf("%02x", fn->hash[j]);
#endif
        putc('\n', stdout);
    }
}


#ifdef USE_SQLITE
static sqlite3 *init_db(const char *db_uri)
{
    sqlite3 *db;
    const char *schema = 
        "CREATE TABLE IF NOT EXISTS binsniff "
        "(id INTEGER PRIMARY KEY ASC, "
        " name TEXT,"
        " start_addr INTEGER, "
        " end_addr   INTEGER, "
        " hash TEXT)\n";

    if (sqlite3_open(db_uri, &db) != SQLITE_OK)
    {
        ERR("Could not open database: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }

    /* Update schema */
    if (sqlite3_exec(db, schema, NULL, NULL, NULL) != SQLITE_OK)
    {
        ERR ("Could not create db schema: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }

    return db;
}
#endif /* USE_SQLITE */


int main(int argc, char **argv)
{
    int opt;
    const char *fname, *db_uri;
#ifdef USE_SQLITE
    sqlite3 *db;
#endif

    /* Args */
    fname = db_uri = NULL;
    while ((opt = getopt(argc, argv, "d:h")) != -1)
    {
        switch (opt)
        {
            case 'd': db_uri = optarg; break;
            case 'h': usage(argv[0]); break;
            default: 
                fprintf(stderr, "Unrecognized argument: -%c", optarg); 
                exit(EXIT_FAILURE);
        }
    }

#ifdef USE_SQLITE
    if (db_uri)
        db = init_db(db_uri);
#endif

    while (optind < argc)
    {
        fname = argv[optind++];

        /* Clear */
        destroy_funcs(&all_funcs);

        /* Create a callgraph */
        build_function_hash_list(fname);

        /* Output the results */
        dump_funcs(all_funcs);

        /* Done */
        bfd_close(bin);
    }

    return 0;
}
