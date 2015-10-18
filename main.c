/******************************************************************************
 * main.c
 *
 * binception - Locate functions in a binary and hash thier code.
 *
 * Copyright (C) 2015, Matt Davis (enferex)
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or (at
 * your option) any later version.
 *             
 * This program is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more
 * details.
 *                             
 * You should have received a copy of the GNU
 * General Public License along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
******************************************************************************/

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


/* To avoid having macros all over the place */
#ifndef USE_SQLITE
typedef void *sqlite3;
#endif

#ifndef USE_OPENSSL
#define MD5_DIGEST_LENGTH 1
#endif


/* Special thanks to the following for providing a very helpful example of how
 * to use libopcodes + libbfd:
 * http://www.toothycat.net/wiki/wiki.pl?Binutils/libopcodes
 */
#define _PR(_tag, ...) do {                            \
        fprintf(stderr, "[binception]" _tag __VA_ARGS__); \
        fputc('\n', stderr);                           \
} while(0)

#define ERR(...) do {             \
    _PR("[error] ", __VA_ARGS__); \
    exit(EXIT_FAILURE);           \
} while(0)

#define WARN(...) do {             \
    _PR("[warning] ", __VA_ARGS__); \
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
    unsigned char hash[MD5_DIGEST_LENGTH];
    struct _func_t *next;
    const char *symbol; /* Symbol/function name if known */
} func_t;
static func_t *all_funcs;


/* Globals accessible from callbacks which have no other means of accessing this
 * data.
 */
static bfd *bin;
static asection *text;
static struct disassemble_info dis_info;
static asymbol **symbols, **sorted_symbols;


/* Address to the current instruction we are processing */
static bfd_vma curr_addr, curr_fn_start_addr;


static void usage(const char *execname)
{
    printf("Usage: %s [executable ...] [-d database] [-v] [-h] [-s]\n"
           " -d <database name>: Database where results are stored\n"
           " -v: Verbose\n",
           " -h: This help message\n"
           " -s: Similarity search: Find what other object files share "
           "functions with object-file (-d must be specified).\n",
           execname);
    exit(EXIT_SUCCESS);
}


/* Given a vm address scan the symbol table  and return the given symbol if
 * found, and NULL otherwise.
 */
static const asymbol *addr_to_symbol(bfd_vma addr)
{
    int i;

    /* If we find an exact match return early */
    for (i=0; sorted_symbols[i]; ++i)
      if (addr == bfd_asymbol_value(sorted_symbols[i]))
        return sorted_symbols[i];

    return NULL;
}


/* Add a function to our list of functions */
static void add_node(func_t *fn)
{
    fn->next = all_funcs;
    all_funcs = fn;
}


static func_t *new_func(bfd_vma st, bfd_vma en, bfd *bfd, asection *text)
{
    const asymbol *sym;
    func_t *fn = calloc(1, sizeof(func_t));

    if (!fn)
    {
        fprintf(stderr, "Not enough memory to allocate a node\n");
        exit(errno);
    }

    fn->st = st;
    fn->en = en;

    if ((sym = addr_to_symbol(st)))
        fn->symbol = sym->name;

#ifdef USE_OPENSSL
    {
        unsigned char *data;
        const file_ptr off = text->filepos + (st - bfd_get_start_address(bfd));
        if (!(data = calloc(en - st, 1)))
        {
            printf("Not enough memory to allocate function data "
                   "(%llu bytes requested)\n", en - st);
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

    free(fn);
    *fnp = NULL;
}


/* Predicate to qsort */
static int cmp_symbol_addr(const void *s1, const void *s2)
{
    bfd_vma a = bfd_asymbol_value(*(const asymbol **)s1);
    bfd_vma b = bfd_asymbol_value(*(const asymbol **)s2);
    if (a < b)
      return -1;
    else if (a == b)
      return 0;
    else
      return 1;
}


/* Read the BFD and obtain the symbols.  We take a hint from addr2line and
 * objdump.  If we have no normal symbols (e.g., the case of a striped binary)
 * then we use the dynamic symbol table.  We only use the latter if there are no
 * regular symbols.
 */
static void get_symbols(bfd *bin)
{
    int i, idx, n_syms, size;
    bool is_dynamic;

    /* Debugging */
    DBG("Symbol table upper bound:         %ld bytes",
        bfd_get_symtab_upper_bound(bin));
    DBG("Dynamic symbol table upper bound: %ld bytes",
        bfd_get_dynamic_symtab_upper_bound(bin));

    /* Get symbol table size (if no regular syms, get dynamic syms)
    * There is always a sentinel symbol (e.g., sizeof(asymbol*)
    */
    is_dynamic = false;
    if ((size = bfd_get_symtab_upper_bound(bin)) <= sizeof(asymbol*))
    {
        if ((size=bfd_get_dynamic_symtab_upper_bound(bin)) <= sizeof(asymbol*))
          ERR("Could not locate any symbols to use");
        is_dynamic = 1;
    }

    /* TODO: For now exit if we only have dynamic symbols */
    if (0 && is_dynamic)
      ERR("Could not locate any symbols (dynamic symbols not supported)");

    if (!(symbols = malloc(size)))
      ERR("Could not allocate enough memory to store the symbol table");

    n_syms = (is_dynamic) ? bfd_canonicalize_dynamic_symtab(bin, symbols) :
                            bfd_canonicalize_symtab(bin, symbols);

    if (!n_syms)
      ERR("Could not locate any symbols");

    DBG("Loaded %d symbols", n_syms);

    /* Sort the symbols for easer searching via location */
    if (!(sorted_symbols = calloc(n_syms, sizeof(asymbol*))))
      ERR("Could not allocate enough memory to store a sorted symbol table");

    /* Ignore symbols with a value(address) of 0 */
    for (i=0, idx=0; i<n_syms; ++i)
      if (bfd_asymbol_value(symbols[i]) != 0)
        sorted_symbols[idx++] = symbols[i];
    qsort(sorted_symbols, idx, sizeof(asymbol *), cmp_symbol_addr);
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

    va_start(va, fmt);
    str = va_arg(va, char *);

    if (!str)
    {
        va_end(va);
        return 0;
    }

    /* If return, compute hash from start to ret */
    if (!curr_fn_start_addr)
      curr_fn_start_addr = curr_addr;
    else if (strncmp(str, "ret", strlen("ret")) == 0)
    {
        func_t *fn = new_func(curr_fn_start_addr, curr_addr, bin, text);
        add_node(fn);
        curr_fn_start_addr = 0;
    }

    va_end(va);
    return 0;
}


/* Open the file and use libopcodes + libfd to create a list 
 * of function hashes.
 */
static void build_function_hash_list(const char *fname)
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
   
    /* Load symbols */ 
    get_symbols(bin);

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
    curr_addr = bfd_get_start_address(bin);
    while ((length = dis(curr_addr, &dis_info)))
    {
        curr_addr += length;
        if ((length < 1) || (curr_addr >= (text->size + bfd_get_start_address(bin))))
            break;
    }
}


static void dump_funcs(const func_t *fns)
{
    int i, j;
    const func_t *fn;

    for (fn=fns; fn; fn=fn->next)
    {
        bfd_vma dist = fn->en - fn->st;
        printf("%d) %p -- %p (%-4.llu bytes)", ++i, fn->st, fn->en, dist);
#ifdef USE_OPENSSL
        printf(" 0x");
        for (j=0; j<MD5_DIGEST_LENGTH; ++j)
          printf("%02x", fn->hash[j]);
#endif
        putc('\n', stdout);
    }
}


static sqlite3 *init_db(const char *db_uri)
{
    sqlite3 *db = NULL;

#ifdef USE_SQLITE
    const char *schema = 
        "CREATE TABLE IF NOT EXISTS binception "
        "(prog TEXT,"
        " start_addr INTEGER, "
        " end_addr INTEGER, "
        " symbol TEXT, "
        " hash TEXT PRIMARY KEY)\n";

    if (sqlite3_open(db_uri, &db) != SQLITE_OK)
    {
        WARN("Could not open database: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }

    /* Update schema */
    if (sqlite3_exec(db, schema, NULL, NULL, NULL) != SQLITE_OK)
    {
        WARN("Could not create db schema: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }
#endif /* USE_SQLITE */

    return db;
}


static const char *hash_to_str(
    const char hash[MD5_DIGEST_LENGTH], 
    char       str[MD5_DIGEST_LENGTH * 2 + 1])
{
    int i;

    for (i=0; i<MD5_DIGEST_LENGTH; ++i)
      sprintf((char *)(str+(i*2)), "%02x", hash[i]);
    str[i*2] = '\0';
    return str;
}


static void save_db(sqlite3 *db, const char *pgname, const func_t *fns)
{
    int i, next_spin;
    const func_t *fn;
    char q[1024];
    const char spinny[] = "-\\|/";

    printf("[%s] Saving records...  ", pgname);
    for (i=0, fn=fns; fn; fn=fn->next, ++i)
    {
        const char *pg = strrchr(pgname, '/') ? strrchr(pgname, '/')+1 : pgname;
        char str[MD5_DIGEST_LENGTH * 2 + 1];
        
        hash_to_str(fn->hash, str);
        snprintf(q, sizeof(q), "INSERT OR REPLACE INTO binception "
                "(prog, start_addr, end_addr, hash, symbol) VALUES "
                "(\"%s\", %lld, %lld, \"%s\", \"%s\")\n",
                pg, fn->st, fn->en, str, fn->symbol);

        if (strlen(q) == sizeof(q))
          WARN("Database insert string truncated");

        if (sqlite3_exec(db, q, NULL, NULL, NULL) != SQLITE_OK)
        {
            WARN("Could not save record to database: %s", sqlite3_errmsg(db));
            WARN("Query: %s", q);
            sqlite3_close(db);
            return;
        }

        if ((i%10) == 0)
        {
            printf("\b%c", spinny[(next_spin++)%4]);
            fflush(NULL);
        }
    }

    printf("\b\n[%s] Saved %d records to database: %s\n",
           pgname, i, sqlite3_db_filename(db, NULL));
}


/* Locate functions in db which have the same hash as functions in 'fns' */
static void calc_similarity(sqlite3 *db, const func_t *fns)
{
#ifdef USE_SQLITE
    int n_matches;
    const func_t *fn;
    char q[1024], str[MD5_DIGEST_LENGTH * 2 + 1];
    sqlite3_stmt *stmt;

    n_matches = 0;
    for (fn=fns; fn; fn=fn->next)
    {
        snprintf(q, sizeof(q),
                 "SELECT DISTINCT prog, symbol "
                 "FROM binception WHERE hash=\"%s\";",
                 hash_to_str(fn->hash, str));

        if (sqlite3_prepare_v2(db, q, strlen(q)+1, &stmt, NULL) != SQLITE_OK)
        {
            WARN("Issue with querying database: %s", sqlite3_errmsg(db));
            continue;
        }

        while (sqlite3_step(stmt) == SQLITE_ROW)
          printf("Found match in: %s, function:%s, %s\n", 
                 sqlite3_column_text(stmt,0),
                 sqlite3_column_text(stmt,1),
                 str);

        sqlite3_finalize(stmt);
    }
#endif /* USE_SQLITE */
}


int main(int argc, char **argv)
{
    int opt;
    _Bool verbose, similarity;
    const char *fname, *db_uri;
    sqlite3 *db;

    /* Args */
    fname = db_uri = NULL;
    verbose = similarity = false;
    while ((opt = getopt(argc, argv, "d:shv")) != -1)
    {
        switch (opt)
        {
            case 'd': db_uri = optarg; break;
            case 'h': usage(argv[0]); break;
            case 'v': verbose = true; break;
            case 's': similarity = true; break;
            default: 
                fprintf(stderr, "Unrecognized argument: -%c", optarg); 
                exit(EXIT_FAILURE);
        }
    }

    if (similarity && !db_uri)
    {
        fprintf(stderr, "The -d option must be specified when using -s\n");
        exit(EXIT_SUCCESS);
    }

    if (db_uri)
      db = init_db(db_uri);

    while (optind < argc)
    {
        fname = argv[optind++];

        /* Create a callgraph */
        build_function_hash_list(fname);

        /* Output the results */
        if (verbose)
          dump_funcs(all_funcs);

        /* Save results to db if we are not performing a similarity search */
        if (!similarity && db_uri)
          save_db(db, fname, all_funcs);
        else if (similarity)
          calc_similarity(db, all_funcs);

        /* Done */
        curr_fn_start_addr = 0;
        bfd_close(bin);
        free(symbols);
        free(sorted_symbols);
        destroy_funcs(&all_funcs);
    }

    return 0;
}
