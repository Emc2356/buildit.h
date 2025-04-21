/*
 * Copyright (c) 2025 Stamelos Vasilis
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _BUILDIT_H
#define _BUILDIT_H

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
    #define BT_WINDOWS
#elif defined(__linux__)
    #define BT_LINUX
    #define BT_POSIX
#elif defined(__APPLE__) && defined(__MACH__)
    #define BT_MACOS
    #define BT_POSIX
#elif defined(unix) || defined(__unix__) || defined(__unix)
    #define BT_POSIX
#endif // Operating system macros

#ifdef BT_WINDOWS
#    define WIN32_LEAN_AND_MEAN
#    define _WINUSER_
#    define _WINGDI_
#    define _IMM_
#    define _WINCON_
#    include <windows.h>
#    include <direct.h>
#    include <shellapi.h>
#else // BT_WINDOWS
#    include <sys/types.h>
#    include <sys/wait.h>
#    include <sys/stat.h>
#    include <unistd.h>
#    include <fcntl.h>
#    include <time.h>
#endif // BT_WINDOWS

#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <stdint.h>

#define BT_UNUSED(x) (void)(x)
#define BT_DEFER(expr) do { result = expr; goto defer; } while(0)
#define BT_TODO(msg) do { fprintf(stderr, "%s:%d: TODO: %s\n", __FILE__, __LINE__, msg); abort(); } while(0)
#define BT_UNREACHABLE(msg) do { fprintf(stderr, "%s:%d: UNREACHABLE: %s\n", __FILE__, __LINE__, msg); abort(); } while(0)

#ifndef BT_ASSERT
    #define BT_ASSERT(expr) assert(expr)
#endif // BT_ASSERT

// BEGIN_SECTION: Utilities
char* bt_escape_argument(const char* input);
// END_SECTION: Utilities

// BEGIN_SECTION: DA
#ifndef BT_DA_INIT_SIZE
#define BT_DA_INIT_SIZE 16
#endif // BT_DA_INIT_SIZE

#ifndef BT_DA_NEW_CAPACITY
#define BT_DA_NEW_CAPACITY(da) ((da)->capacity == 0 ? BT_DA_INIT_SIZE : (da)->capacity*BT_DA_GROWTH_RATE)
#define BT_DA_GROWTH_RATE 2
#endif // BT_DA_NEW_CAPACITY

#define bt_da_init(da, cap__) do {                           \
    (da)->items = bt_arena_malloc(sizeof(*da->items)*cap__); \
    (da)->capacity = cap__;(da)->size = 0;                   \
    } while(0)

#define bt_da_append(da, item) do {                                   \
        if ((da)->size >= (da)->capacity) {                           \
            (da)->items = bt_arena_realloc((da)->items,               \
                        (da)->capacity*sizeof(*(da)->items),          \
                        BT_DA_NEW_CAPACITY(da)*sizeof(*(da)->items)); \
            (da)->capacity = BT_DA_NEW_CAPACITY(da);                  \
        }                                                             \
        (da)->items[(da)->size++] = (item);                           \
    } while (0)

#define bt_da_append_many(da, new_items, count) do {                                   \
        if (new_items == NULL || count == 0) {  break; }                               \
        if ((da)->size + (count) >= (da)->capacity) {                                  \
            size_t bt_da_append_many_new_cap##__LINE__ = BT_DA_NEW_CAPACITY(da);       \
            while ((da)->size + (count) > bt_da_append_many_new_cap##__LINE__) {       \
                bt_da_append_many_new_cap##__LINE__ *= BT_DA_GROWTH_RATE;              \
            }                                                                          \
            (da)->items = bt_arena_realloc((da)->items,                                \
                            (da)->capacity*sizeof(*(da)->items),                       \
                            bt_da_append_many_new_cap##__LINE__*sizeof(*(da)->items)); \
            (da)->capacity = bt_da_append_many_new_cap##__LINE__;                      \
        }                                                                              \
        memcpy((da)->items + (da)->size, new_items, (count)*sizeof(*(da)->items));     \
        (da)->size += count;                                                           \
    } while (0)

#define bt_da_pop(da) do { ((da)->size--); } while (0)

#define bt_da_popi(da, index) do {                                      \
        if (index == (da)->size-1) { bt_da_pop(da); } else {            \
            memmove(&(((da)->items[(index)])),                          \
                    &(((da)->items[(index)+1])),                        \
                    ((da)->size - (index) - 1)*sizeof(*((da)->items))); \
            (da)->size--;                                               \
        }                                                               \
    } while (0)

#define bt_da_extend(da, other_da) bt_da_append_many((da), ((other_da)->items), ((other_da)->size))

#define bt_da_foreach(counter, variable, dynamic_array)                                                      \
    if ((dynamic_array)->size > 0) {                                                                         \
        (variable) = (dynamic_array)->items[0];                                                              \
    }                                                                                                        \
    for ((counter) = 0; (counter) < (dynamic_array)->size; (variable) = (dynamic_array)->items[++(counter)])

#define bt_da_foreach_ref(counter, variable, dynamic_array)                                                     \
    if ((dynamic_array)->size > 0) {                                                                            \
        (variable) = (dynamic_array)->items;                                                                    \
    }                                                                                                           \
    for ((counter) = 0; (counter) < (dynamic_array)->size; (variable) = (dynamic_array)->items + (++(counter)))

#define bt_da_free(da) if ((da)->capacity > 0) { bt_arena_free((da)->items); (da)->capacity = 0; (da)->size = 0; (da)->items = NULL; }

typedef struct Bt_String_Array {
    const char** items;
    size_t size;
    size_t capacity;
} Bt_String_Array;
// END_SECTION: DA

// BEGIN_SECTION: Log
typedef enum {
    BT_DEBUG,
    BT_INFO,
    BT_WARNING,
    BT_ERROR,
    BT_FATAL,
    BT_NOLOG,
} Bt_Log_Level;

void bt_log(Bt_Log_Level level, const char *fmt, ...);
// everything bellow min_log_level will be suppressed
void bt_set_min_log_level(Bt_Log_Level min_log_level);
Bt_Log_Level bt_get_min_log_level(void);

#define bt_log_debug(...)   bt_log(BT_DEBUG, __VA_ARGS__)
#define bt_log_info(...)    bt_log(BT_INFO, __VA_ARGS__)
#define bt_log_warning(...) bt_log(BT_WARNING, __VA_ARGS__)
#define bt_log_error(...)   bt_log(BT_ERROR, __VA_ARGS__)
#define bt_log_fatal(...)   bt_log(BT_FATAL, __VA_ARGS__)
// END_SECTION: Log

// BEGIN_SECTION: Buffer Reader/Writer
typedef struct Bt_Buffer_Reader {
    const uint8_t* buffer;
    uint64_t buffer_size;
    uint64_t offset;
} Bt_Buffer_Reader;

typedef struct Bt_Buffer_Writer {
    uint8_t* buffer;
    uint64_t size;
    uint64_t capacity;
} Bt_Buffer_Writer;

bool bt_buffer_reader_is_empty(Bt_Buffer_Reader* br);
char* bt_buffer_reader_extract_string(Bt_Buffer_Reader* br, uint32_t* size);
void bt_buffer_reader_consume_string(Bt_Buffer_Reader* br);
uint64_t bt_buffer_reader_extract_u64(Bt_Buffer_Reader* br);
void bt_buffer_reader_consume_u64(Bt_Buffer_Reader* br);
int64_t bt_buffer_reader_extract_i64(Bt_Buffer_Reader* br);
void bt_buffer_reader_consume_i64(Bt_Buffer_Reader* br);
uint32_t bt_buffer_reader_extract_u32(Bt_Buffer_Reader* br);
void bt_buffer_reader_consume_u32(Bt_Buffer_Reader* br);
int32_t bt_buffer_reader_extract_i32(Bt_Buffer_Reader* br);
void bt_buffer_reader_consume_i32(Bt_Buffer_Reader* br);
uint8_t bt_buffer_reader_extract_u8(Bt_Buffer_Reader* br);
void bt_buffer_reader_consume_u8(Bt_Buffer_Reader* br);
int8_t bt_buffer_reader_extract_i8(Bt_Buffer_Reader* br);
void bt_buffer_reader_consume_i8(Bt_Buffer_Reader* br);
void bt_buffer_writer_init(Bt_Buffer_Writer* bw, uint32_t init_size);
void bt_buffer_writer_free(Bt_Buffer_Writer* bw);
void bt_buffer_writer_insert_string(Bt_Buffer_Writer* bw, const char* str);
void bt_buffer_writer_insert_i64(Bt_Buffer_Writer* bw, int64_t value);
void bt_buffer_writer_insert_u64(Bt_Buffer_Writer* bw, uint64_t value);
void bt_buffer_writer_insert_i32(Bt_Buffer_Writer* bw, int32_t value);
void bt_buffer_writer_insert_u32(Bt_Buffer_Writer* bw, uint32_t value);
void bt_buffer_writer_insert_i8(Bt_Buffer_Writer* bw, int8_t value);
void bt_buffer_writer_insert_u8(Bt_Buffer_Writer* bw, uint8_t value);
// END_SECTION: Buffer Reader/Writer

// BEGIN_SECTION: String Builder
typedef struct {
    char *items;
    size_t size;
    size_t capacity;
} Bt_String_Builder;

#define bt_sb_append_buf(sb, buf, size) bt_da_append_many(sb, buf, size)
#define bt_sb_append_cstr(sb, cstr) bt_da_append_many(sb, cstr, strlen(cstr))
#define bt_sb_append_char(sb, c__) bt_da_append(sb, (c__))
#define bt_sb_append_null(sb) bt_da_append(sb, '\0')
#define bt_sb_as_cstr(sb) (sb)->items
#define bt_sb_free(sb) bt_da_free(sb)
// END_SECTION: String Builder

// BEGIN_SECTION: String View
typedef struct Bt_String_View {
    const char* data;
   size_t size;
} Bt_String_View;

Bt_String_View bt_sv_from_sb(Bt_String_Builder* sb);
Bt_String_View bt_sv_from_cstr(const char* cstr);
Bt_String_View bt_sv_from_parts(const char* data, size_t size);
Bt_String_View bt_sv_trim(Bt_String_View sv);
Bt_String_View bt_sv_trim_left(Bt_String_View sv);
Bt_String_View bt_sv_trim_right(Bt_String_View sv);
bool bt_sv_eq(Bt_String_View a, Bt_String_View b);
bool bt_sv_startswith(Bt_String_View sv, char* cstr);
bool bt_sv_endswith(Bt_String_View sv, char *cstr);

#define BT_SV_Fmt "%.*s"
#define BT_SV_Arg(sv) (int) (sv).size, (sv).data

typedef struct Bt_String_Views {
    Bt_String_View* items;
    size_t size;
    size_t capacity;
} Bt_String_Views;
// END_SECTION: String View

// BEGIN_SECTION: Arena
void bt_arena_init(size_t page_size);
void bt_arena_destroy(void);
size_t bt_arena_get_checkpoint(void);
void bt_arena_rewind(size_t checkpoint);
void* bt_arena_malloc(size_t size);
void* bt_arena_memalign(size_t size, size_t alignment);
void* bt_arena_calloc(size_t count, size_t size);
void* bt_arena_realloc(void* ptr, size_t old_size, size_t new_size);
void bt_arena_free(void* ptr); /* can only deallocate the last allocated chunk */
char* bt_arena_strdup(const char* str);
char* bt_arena_strndup(const char* str, size_t n);
void* bt_arena_memdup(const void* buffer, size_t buffer_size);
char* bt_arena_strcat(const char* str1, const char* str2);
char* bt_arena_cstr_from_sv(const Bt_String_View* sv);
char* bt_arena_sprintf(const char* format, ...);
#define bt_arena_join_strings(sep, str1, ...) arena__join_strings(sep, str1, __VA_ARGS__, NULL)
char* bt_arena__join_strings(const char* sep, const char* str1, ...);
// END_SECTION: Arena

// BEGIN_SECTION: Time
void bt_sleep(size_t ms);
// *tp contains the current time in nano seconds, return false on failure
bool bt_time_perf_counter(int64_t *tp);

#define BT_TIMEIT(name, body) do {                                                                                        \
        int64_t bt__timeit__start_var##__LINE__, bt__timeit__end_var##__LINE__;                                           \
        bt_time_perf_counter(&bt__timeit__start_var##__LINE__);                                                           \
        body;                                                                                                             \
        bt_time_perf_counter(&bt__timeit__end_var##__LINE__);                                                             \
        bt_log(BT_INFO, "%s took %lfs", name,                                                                             \
            ((double)bt__timeit__end_var##__LINE__ - (double)bt__timeit__start_var##__LINE__) / (1000 * 1000 * 1000));    \
    } while(0)
// END_SECTION: Time

// BEGIN_SECTION: Command
typedef struct Bt_Process Bt_Process;
typedef struct Bt_Cmd {
    const char** items;
    size_t size;
    size_t capacity;
    // only used by bt_execute_command_queue
    Bt_Process* process;
    const char* message;
    const char* fail_message;
} Bt_Cmd;

typedef struct Bt_Cmds {
    Bt_Cmd* items;
    size_t size;
    size_t capacity;
} Bt_Cmds;

#define bt_cmd_append(cmd, arg) bt_da_append(cmd, arg)
#define bt_cmd_extend(cmd, other) bt_da_extend(cmd, other)
#define bt_cmd_free(cmd) bt_da_free(cmd)
#define bt_cmd_add_many(cmd, ...) bt__cmd_add_many(cmd, __VA_ARGS__, NULL)
void bt__cmd_add_many(Bt_Cmd* cmd, ...);

// async process with combined stdout/stderr and cant be interacted with
Bt_Process* bt_process_start(Bt_Cmd* cmd);
bool bt_process_destroy(Bt_Process* process);
bool bt_process_kill(Bt_Process* process);
bool bt_process_is_alive(Bt_Process* process);
bool bt_process_wait_for_completion(Bt_Process* process, int* returncode);
bool bt_process_get_return_code(Bt_Process* process, int* returncode);
int bt_process_read_output(Bt_Process* process, void* buffer, size_t buffer_size);

bool bt_execute_cmd(const Bt_Cmd* cmd, int* returncode, const char* cwd);
#define bt_execute_command(returncode, cwd, ...) bt__execute_command(returncode, cwd, __VA_ARGS__, NULL)
bool bt__execute_command(int* returncode, const char* cwd, ...);
bool bt_execute_command_queue(Bt_Cmds* command_queue, size_t command_queue_size, size_t max_active_processes);
// END_SECTION: Command

// BEGIN_SECTION: Compiler
typedef struct Bt_Compiler {
    const char* name;

    // usually just contains the name of the program but it can
    // contain extra agruments
    Bt_String_Array base_c_compile_command;
    Bt_String_Array base_cxx_compile_command;
    Bt_String_Array base_linker_command;

    const char* executable_extension;

    // MANDATORY
    void (*generate_static_library)(struct Bt_Compiler* compiler, Bt_Cmd* cmd, Bt_String_Array* files, const char* output_location, const char* name);
    const char* (*get_static_library_name)(struct Bt_Compiler* compiler, const char* name, const char* output_location);

    void (*change_c_compiler_name)(struct Bt_Compiler* compiler, const char* c_compiler);
    void (*change_cxx_compiler_name)(struct Bt_Compiler* compiler, const char* cpp_compiler);
    void (*change_linker_command_name)(struct Bt_Compiler* compiler, const char* linker);

    void (*add_include_directory)(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const char* directory);
    void (*add_include_directories)(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const Bt_String_Array* directories);
    void (*add_library_directory)(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const char* directory);
    void (*add_library_directories)(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const Bt_String_Array* directories);

    void (*add_library)(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const char* library_name);
    void (*add_libraries)(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const Bt_String_Array* library_names);

    // define_value can be NULL
    void (*add_define)(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const char* define_name, const char* define_value);

    void (*add_source_file)(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const char* source_file);
    void (*add_source_files)(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const Bt_String_Array* source_files);
    void (*add_file_to_linker)(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const char* source_file);
    void (*add_files_to_linker)(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const Bt_String_Array* source_files);

    void (*specify_output_name)(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const char* output_name);

    void (*no_linking)(struct Bt_Compiler* compiler, Bt_Cmd* cmd); // essentially only the object file

    void (*add_precompiled_header)(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const char* filename);
    void (*add_precompiled_headers)(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const Bt_String_Array* filenames);

    char* (*source_file_to_object_filename)(struct Bt_Compiler* compiler, const char* build_directory, const char* filename);
    char* (*source_file_to_precompiled_header_filename)(struct Bt_Compiler* compiler, const char* filename);

    // OPTIONAL
    void (*turn_on_optimizations)(struct Bt_Compiler* compiler, Bt_Cmd* cmd);
    void (*enable_all_warnings)(struct Bt_Compiler* compiler, Bt_Cmd* cmd);
    void (*treat_warnings_as_errors)(struct Bt_Compiler* compiler, Bt_Cmd* cmd);
    void (*generate_debug_symbols)(struct Bt_Compiler* compiler, Bt_Cmd* cmd);

    // can be extra data that each backend uses
    void* extra_data;
} Bt_Compiler;

// c_standard and cxx_standard can be null
// example usage bt_create_clang_compiler("c99", null);
// example usage bt_create_clang_compiler("gnu99", "c++11");
Bt_Compiler* bt_create_clang_compiler(char* c_standard, char* cxx_standard);
void bt_destroy_clang_compiler(Bt_Compiler* clang_compiler);
// default is: ["ar", "rcs", "-o"]
void bt_clang_compiler_change_archive_command(Bt_Compiler* compiler, Bt_Cmd* command);

// c_standard and cxx_standard can be null
// example usage bt_create_clang_compiler("c99", null);
// example usage bt_create_clang_compiler("gnu99", "c++11");
Bt_Compiler* bt_create_gnu_compiler(char* c_standard, char* cxx_standard);
void bt_destroy_gnu_compiler(Bt_Compiler* clang_compiler);
// default is: ["ar", "rcs", "-o"]
void bt_gnu_compiler_change_archive_command(Bt_Compiler* compiler, Bt_Cmd* command);

const char* bt_get_build_directory(void);
void bt_set_build_directory(const char* build_directory);

// shortcuts so you dont have to type compiler->func(compiler, args)
void bt_compiler_set(Bt_Compiler* compiler);
Bt_Compiler* bt_compiler_get(void);
Bt_String_Array* bt_compiler_get_base_c_compile_command(void);
Bt_String_Array* bt_compiler_get_base_cxx_compile_command(void);
Bt_String_Array* bt_compiler_get_base_linker_command(void);
const char* bt_compiler_get_executable_extension(void);
void bt_compiler_generate_static_library(Bt_Cmd* cmd, Bt_String_Array* files, const char* output_location, const char* name);
const char* bt_compiler_get_static_library_name(const char* name, const char* output_location);
void bt_compiler_change_c_compiler_name(char* c_compiler);
void bt_compiler_change_cxx_compiler_name(char* cpp_compiler);
void bt_compiler_change_linker_command_name(char* linker);
void bt_compiler_add_include_directory(Bt_Cmd* cmd, char* directory);
void bt_compiler_add_include_directories(Bt_Cmd* cmd, const Bt_String_Array* directories);
void bt_compiler_add_library_directory(Bt_Cmd* cmd, const char* directory);
void bt_compiler_add_library_directories(Bt_Cmd* cmd, const Bt_String_Array* directories);
void bt_compiler_add_library(Bt_Cmd* cmd, const char* library_name);
void bt_compiler_add_libraries(Bt_Cmd* cmd, const Bt_String_Array* library_names);
void bt_compiler_add_define(Bt_Cmd* cmd, const char* define_name, const char* define_value);
void bt_compiler_add_source_file(Bt_Cmd* cmd, const char* source_file);
void bt_compiler_add_source_files(Bt_Cmd* cmd, const Bt_String_Array* source_files);
void bt_compiler_add_file_to_linker(Bt_Cmd* cmd, const char* source_file);
void bt_compiler_add_files_to_linker(Bt_Cmd* cmd, const Bt_String_Array* source_files);
void bt_compiler_specify_output_name(Bt_Cmd* cmd, char* output_name);
void bt_compiler_no_linking(Bt_Cmd* cmd); // essentially only the object file
void bt_compiler_add_precompiled_header(Bt_Cmd* cmd, const char* filename);
void bt_compiler_add_precompiled_headers(Bt_Cmd* cmd, const Bt_String_Array* filenames);
char* bt_compiler_source_file_to_object_filename(const char* build_directory, const char* filename);
char* bt_compiler_source_file_to_precompiled_header_filename(const char* filename);
void bt_compiler_turn_on_optimizations(Bt_Cmd* cmd);
void bt_compiler_enable_all_warnings(Bt_Cmd* cmd);
void bt_compiler_treat_warnings_as_errors(Bt_Cmd* cmd);
void bt_compiler_generate_debug_symbols(Bt_Cmd* cmd);
// END_SECTION: Compiler

// BEGIN_SECTION: BuildSys
typedef enum Bt_Compile_Options { // @TODO
    BT_COMPO_NONE = 0,
    BT_COMPO_OPTIMIZED = 1 << 0,
    BT_COMPO_DEBUG_SYMBOLS = 1 << 1,
    BT_COMPO_EXTRA_WARNINGS = 1 << 2,
    BT_COMPO_FAIL_ON_WARNING = 1 << 3,
} Bt_Compile_Options;

typedef struct Bt_Define {
    const char* name;
    const char* value;
} Bt_Define;

typedef struct Bt_Defines {
    Bt_Define* items;
    size_t size;
    size_t capacity;
} Bt_Defines;

typedef struct Bt_Static_Library {
    const char* name;
    // output_location/<formated name goes here>
    // ex output_location/libImGui.a
    const char* output_location;
    Bt_String_Array sources;
    Bt_String_Array include_directories;
    Bt_String_Array precompiled_headers; // @TODO
    Bt_String_Array extra_build_flags;
    Bt_Defines defines;
    Bt_String_Array library_directories;
    Bt_String_Array libraries;

    // other static/dynamic libraries that it depends on
    Bt_String_Array dependencies;

    Bt_Compile_Options compile_options;
} Bt_Static_Library;

void bt_slib_set_name(Bt_Static_Library* slib, const char* name);
void bt_slib_set_output_location(Bt_Static_Library* slib, const char* output_location);
void bt_slib_add_source(Bt_Static_Library* slib, const char* source);
void bt_slib_add_include_directory(Bt_Static_Library* slib, const char* include_directory);
void bt_slib_add_precompiled_header(Bt_Static_Library* slib, const char* precompiled_header);
void bt_slib_add_extra_build_flag(Bt_Static_Library* slib, const char* extra_build_flag);
void bt_slib_add_define(Bt_Static_Library* slib, const char* define_name, const char* define_value);
void bt_slib_add_library_directory(Bt_Static_Library* slib, const char* library_directory);
void bt_slib_add_library(Bt_Static_Library* slib, const char* library);
void bt_slib_add_dependency(Bt_Static_Library* slib, const char* dependency);

typedef struct Bt_Static_Libraries {
    Bt_Static_Library* items;
    size_t size;
    size_t capacity;
} Bt_Static_Libraries;

typedef struct Bt_Executable {
    const char* name;
    const char* output_location;
    Bt_String_Array sources;
    Bt_String_Array precompiled_headers; // @TODO
    Bt_String_Array include_directories;
    Bt_Defines defines;
    // external libraries
    Bt_String_Array libraries;
    Bt_String_Array library_directories;
    Bt_String_Array extra_build_flags;
    Bt_String_Array extra_link_flags;
    // a string of the name of the static library that is build by buildit
    Bt_String_Array dependencies;

    Bt_Compile_Options compile_options;
} Bt_Executable;

void bt_exe_set_name(Bt_Executable* exe, const char* name);
void bt_exe_set_output_location(Bt_Executable* exe, const char* output_location);
void bt_exe_add_source(Bt_Executable* exe, const char* source);
void bt_exe_add_precompiled_header(Bt_Executable* exe, const char* precompiled_header);
void bt_exe_add_include_directory(Bt_Executable* exe, const char* include_directory);
void bt_exe_add_define(Bt_Executable* exe, const char* define_name, const char* define_value);
void bt_exe_add_library(Bt_Executable* exe, const char* library);
void bt_exe_add_library_directory(Bt_Executable* exe, const char* library_directory);
void bt_exe_add_extra_build_flag(Bt_Executable* exe, const char* extra_build_flag);
void bt_exe_add_extra_link_flag(Bt_Executable* exe, const char* extra_link_flag);
void bt_exe_add_dependency(Bt_Executable* exe, const char* dependency);

typedef struct Bt_Executables {
    Bt_Executable* items;
    size_t size;
    size_t capacity;
} Bt_Executables;

// zero initialize before use
typedef struct Bt_Build_Spec {
    Bt_String_Array include_directories;
    Bt_String_Array library_directories;
    Bt_String_Array libraries;
    Bt_Defines extra_defines;
    Bt_String_Array extra_build_flags;
    Bt_String_Array extra_link_flags;

    Bt_Static_Libraries static_libraries;
    Bt_Executables executables;
} Bt_Build_Spec;

void bt_bspec_add_include_directory(Bt_Build_Spec* spec, const char* include_directory);
void bt_bspec_add_library_directory(Bt_Build_Spec* spec, const char* library_directory);
void bt_bspec_add_library(Bt_Build_Spec* spec, const char* library);
void bt_bspec_add_extra_define(Bt_Build_Spec* spec, const char* define_name, const char* define_value);
void bt_bspec_add_extra_build_flag(Bt_Build_Spec* spec, const char* extra_build_flag);
void bt_bspec_add_extra_link_flag(Bt_Build_Spec* spec, const char* extra_link_flag);
void bt_bspec_add_static_library(Bt_Build_Spec* spec, Bt_Static_Library* static_library);
void bt_bspec_add_executable(Bt_Build_Spec* spec, Bt_Executable* executable);

bool bt_init(const char* build_directory);
void bt_shutdown(void);
int bt_get_cpu_core_count(void);
bool bt_build(const Bt_Build_Spec* spec, size_t max_active_processes);
bool bt_bspec_is_malformed(const Bt_Build_Spec* spec);
void bt_rebuild_self_if_needed(const char* source_file, const char* output_location, const char* final_executable_name);
bool bt_dump_compile_commands_json(const Bt_Build_Spec* spec, const char* compile_commands_json_path);
// END_SECTION: BuildSys

// BEGIN_SECTION: Fs
#define bt_concat_paths(...) bt__concat__paths(__VA_ARGS__, NULL)
char* bt__concat__paths(const char* first, ...);
bool bt_path_exists(const char* path);
bool bt_read_entire_file(const char* path, Bt_String_Builder* sb);
bool bt_write_entire_file(const char *path, const void *data, size_t size);
uint64_t bt_get_get_last_modification_date(const char* path);
const char* bt_parent(const char* path);
bool bt_path_is_file(const char* path);
bool bt_path_is_directory(const char* path);
bool bt_mkdir_parent_if_not_exists(const char* path);
bool bt_mkdir_recursivly_if_not_exists(const char* path);
bool bt_mkdir_if_not_exists(const char* path);
// END_SECTION: Fs

// BEGIN_SECTION: Special Files
void bt_log_file_update_entry(const char* name);
uint64_t bt_log_file_get_time(const char* name);
bool bt_was_file_modified(const char* filename);
bool bt_was_file_modified_from_includes(const char* target_filepath, Bt_String_Array include_paths_to_search);
// END_SECTION: Special Files

#endif // _BUILDIT_H

#ifdef BUILDIT_IMPLEMENTATION

// BEGIN_SECTION: External Libraries
    // BEGIN_SECTION: subprocess.h
        /*
        The latest version of this library is available on GitHub;
        https://github.com/sheredom/subprocess.h
        */

        /*
        This is free and unencumbered software released into the public domain.

        Anyone is free to copy, modify, publish, use, compile, sell, or
        distribute this software, either in source code form or as a compiled
        binary, for any purpose, commercial or non-commercial, and by any
        means.

        In jurisdictions that recognize copyright laws, the author or authors
        of this software dedicate any and all copyright interest in the
        software to the public domain. We make this dedication for the benefit
        of the public at large and to the detriment of our heirs and
        successors. We intend this dedication to be an overt act of
        relinquishment in perpetuity of all present and future rights to this
        software under copyright law.

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
        EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
        IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
        OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
        ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
        OTHER DEALINGS IN THE SOFTWARE.

        For more information, please refer to <http://unlicense.org/>
        */

        #ifndef SHEREDOM_SUBPROCESS_H_INCLUDED
        #define SHEREDOM_SUBPROCESS_H_INCLUDED

        #if defined(_MSC_VER)
        #pragma warning(push, 1)

        /* disable warning: '__cplusplus' is not defined as a preprocessor macro,
        * replacing with '0' for '#if/#elif' */
        #pragma warning(disable : 4668)
        #endif

        #include <stdio.h>
        #include <string.h>

        #if defined(_MSC_VER)
        #pragma warning(pop)
        #endif

        #if defined(__TINYC__)
        #define SUBPROCESS_ATTRIBUTE(a) __attribute((a))
        #else
        #define SUBPROCESS_ATTRIBUTE(a) __attribute__((a))
        #endif

        #if defined(_MSC_VER)
        #define subprocess_pure
        #define subprocess_weak __inline
        #define subprocess_tls __declspec(thread)
        #elif defined(__MINGW32__)
        #define subprocess_pure SUBPROCESS_ATTRIBUTE(pure)
        #define subprocess_weak static SUBPROCESS_ATTRIBUTE(used)
        #define subprocess_tls __thread
        #elif defined(__clang__) || defined(__GNUC__) || defined(__TINYC__)
        #define subprocess_pure SUBPROCESS_ATTRIBUTE(pure)
        #define subprocess_weak SUBPROCESS_ATTRIBUTE(weak)
        #define subprocess_tls __thread
        #else
        #error Non clang, non gcc, non MSVC compiler found!
        #endif

        struct subprocess_s;

        enum subprocess_option_e {
        // stdout and stderr are the same FILE.
        subprocess_option_combined_stdout_stderr = 0x1,

        // The child process should inherit the environment variables of the parent.
        subprocess_option_inherit_environment = 0x2,

        // Enable asynchronous reading of stdout/stderr before it has completed.
        subprocess_option_enable_async = 0x4,

        // Enable the child process to be spawned with no window visible if supported
        // by the platform.
        subprocess_option_no_window = 0x8,

        // Search for program names in the PATH variable. Always enabled on Windows.
        // Note: this will **not** search for paths in any provided custom environment
        // and instead uses the PATH of the spawning process.
        subprocess_option_search_user_path = 0x10
        };

        #if defined(__cplusplus)
        extern "C" {
        #endif

        /// @brief Create a process.
        /// @param command_line An array of strings for the command line to execute for
        /// this process. The last element must be NULL to signify the end of the array.
        /// The memory backing this parameter only needs to persist until this function
        /// returns.
        /// @param options A bit field of subprocess_option_e's to pass.
        /// @param out_process The newly created process.
        /// @return On success zero is returned.
        subprocess_weak int subprocess_create(const char *const command_line[],
                                            int options,
                                            struct subprocess_s *const out_process);

        /// @brief Create a process (extended create).
        /// @param command_line An array of strings for the command line to execute for
        /// this process. The last element must be NULL to signify the end of the array.
        /// The memory backing this parameter only needs to persist until this function
        /// returns.
        /// @param options A bit field of subprocess_option_e's to pass.
        /// @param environment An optional array of strings for the environment to use
        /// for a child process (each element of the form FOO=BAR). The last element
        /// must be NULL to signify the end of the array.
        /// @param out_process The newly created process.
        /// @return On success zero is returned.
        ///
        /// If `options` contains `subprocess_option_inherit_environment`, then
        /// `environment` must be NULL.
        subprocess_weak int
        subprocess_create_ex(const char *const command_line[], int options,
                            const char *const environment[],
                            struct subprocess_s *const out_process);

        /// @brief Get the standard input file for a process.
        /// @param process The process to query.
        /// @return The file for standard input of the process.
        ///
        /// The file returned can be written to by the parent process to feed data to
        /// the standard input of the process.
        subprocess_pure subprocess_weak FILE *
        subprocess_stdin(const struct subprocess_s *const process);

        /// @brief Get the standard output file for a process.
        /// @param process The process to query.
        /// @return The file for standard output of the process.
        ///
        /// The file returned can be read from by the parent process to read data from
        /// the standard output of the child process.
        subprocess_pure subprocess_weak FILE *
        subprocess_stdout(const struct subprocess_s *const process);

        /// @brief Get the standard error file for a process.
        /// @param process The process to query.
        /// @return The file for standard error of the process.
        ///
        /// The file returned can be read from by the parent process to read data from
        /// the standard error of the child process.
        ///
        /// If the process was created with the subprocess_option_combined_stdout_stderr
        /// option bit set, this function will return NULL, and the subprocess_stdout
        /// function should be used for both the standard output and error combined.
        subprocess_pure subprocess_weak FILE *
        subprocess_stderr(const struct subprocess_s *const process);

        /// @brief Wait for a process to finish execution.
        /// @param process The process to wait for.
        /// @param out_return_code The return code of the returned process (can be
        /// NULL).
        /// @return On success zero is returned.
        ///
        /// Joining a process will close the stdin pipe to the process.
        subprocess_weak int subprocess_join(struct subprocess_s *const process,
                                            int *const out_return_code);

        /// @brief Destroy a previously created process.
        /// @param process The process to destroy.
        /// @return On success zero is returned.
        ///
        /// If the process to be destroyed had not finished execution, it may out live
        /// the parent process.
        subprocess_weak int subprocess_destroy(struct subprocess_s *const process);

        /// @brief Terminate a previously created process.
        /// @param process The process to terminate.
        /// @return On success zero is returned.
        ///
        /// If the process to be destroyed had not finished execution, it will be
        /// terminated (i.e killed).
        subprocess_weak int subprocess_terminate(struct subprocess_s *const process);

        /// @brief Read the standard output from the child process.
        /// @param process The process to read from.
        /// @param buffer The buffer to read into.
        /// @param size The maximum number of bytes to read.
        /// @return The number of bytes actually read into buffer. Can only be 0 if the
        /// process has complete.
        ///
        /// The only safe way to read from the standard output of a process during it's
        /// execution is to use the `subprocess_option_enable_async` option in
        /// conjunction with this method.
        subprocess_weak unsigned
        subprocess_read_stdout(struct subprocess_s *const process, char *const buffer,
                            unsigned size);

        /// @brief Read the standard error from the child process.
        /// @param process The process to read from.
        /// @param buffer The buffer to read into.
        /// @param size The maximum number of bytes to read.
        /// @return The number of bytes actually read into buffer. Can only be 0 if the
        /// process has complete.
        ///
        /// The only safe way to read from the standard error of a process during it's
        /// execution is to use the `subprocess_option_enable_async` option in
        /// conjunction with this method.
        subprocess_weak unsigned
        subprocess_read_stderr(struct subprocess_s *const process, char *const buffer,
                            unsigned size);

        /// @brief Returns if the subprocess is currently still alive and executing.
        /// @param process The process to check.
        /// @return If the process is still alive non-zero is returned.
        subprocess_weak int subprocess_alive(struct subprocess_s *const process);

        #if defined(__cplusplus)
        #define SUBPROCESS_CAST(type, x) static_cast<type>(x)
        #define SUBPROCESS_PTR_CAST(type, x) reinterpret_cast<type>(x)
        #define SUBPROCESS_CONST_CAST(type, x) const_cast<type>(x)
        #define SUBPROCESS_NULL NULL
        #else
        #define SUBPROCESS_CAST(type, x) ((type)(x))
        #define SUBPROCESS_PTR_CAST(type, x) ((type)(x))
        #define SUBPROCESS_CONST_CAST(type, x) ((type)(x))
        #define SUBPROCESS_NULL 0
        #endif

        #if !defined(_WIN32)
        #include <signal.h>
        #include <spawn.h>
        #include <stdlib.h>
        #include <sys/types.h>
        #include <sys/wait.h>
        #include <unistd.h>
        #endif

        #if defined(_WIN32)

        #if (_MSC_VER < 1920)
        #ifdef _WIN64
        typedef __int64 subprocess_intptr_t;
        typedef unsigned __int64 subprocess_size_t;
        #else
        typedef int subprocess_intptr_t;
        typedef unsigned int subprocess_size_t;
        #endif
        #else
        #include <inttypes.h>

        typedef intptr_t subprocess_intptr_t;
        typedef size_t subprocess_size_t;
        #endif

        #ifdef __clang__
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wreserved-identifier"
        #endif

        typedef struct _PROCESS_INFORMATION *LPPROCESS_INFORMATION;
        typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;
        typedef struct _STARTUPINFOA *LPSTARTUPINFOA;
        typedef struct _OVERLAPPED *LPOVERLAPPED;

        #ifdef __clang__
        #pragma clang diagnostic pop
        #endif

        #ifdef _MSC_VER
        #pragma warning(push, 1)
        #endif
        #ifdef __MINGW32__
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wpedantic"
        #endif

        struct subprocess_subprocess_information_s {
        void *hProcess;
        void *hThread;
        unsigned long dwProcessId;
        unsigned long dwThreadId;
        };

        struct subprocess_security_attributes_s {
        unsigned long nLength;
        void *lpSecurityDescriptor;
        int bInheritHandle;
        };

        struct subprocess_startup_info_s {
        unsigned long cb;
        char *lpReserved;
        char *lpDesktop;
        char *lpTitle;
        unsigned long dwX;
        unsigned long dwY;
        unsigned long dwXSize;
        unsigned long dwYSize;
        unsigned long dwXCountChars;
        unsigned long dwYCountChars;
        unsigned long dwFillAttribute;
        unsigned long dwFlags;
        unsigned short wShowWindow;
        unsigned short cbReserved2;
        unsigned char *lpReserved2;
        void *hStdInput;
        void *hStdOutput;
        void *hStdError;
        };

        struct subprocess_overlapped_s {
        uintptr_t Internal;
        uintptr_t InternalHigh;
        union {
            struct {
            unsigned long Offset;
            unsigned long OffsetHigh;
            } DUMMYSTRUCTNAME;
            void *Pointer;
        } DUMMYUNIONNAME;

        void *hEvent;
        };

        #ifdef __MINGW32__
        #pragma GCC diagnostic pop
        #endif
        #ifdef _MSC_VER
        #pragma warning(pop)
        #endif

        __declspec(dllimport) unsigned long __stdcall GetLastError(void);
        __declspec(dllimport) int __stdcall SetHandleInformation(void *, unsigned long,
                                                                unsigned long);
        __declspec(dllimport) int __stdcall CreatePipe(void **, void **,
                                                    LPSECURITY_ATTRIBUTES,
                                                    unsigned long);
        __declspec(dllimport) void *__stdcall CreateNamedPipeA(
            const char *, unsigned long, unsigned long, unsigned long, unsigned long,
            unsigned long, unsigned long, LPSECURITY_ATTRIBUTES);
        __declspec(dllimport) int __stdcall ReadFile(void *, void *, unsigned long,
                                                    unsigned long *, LPOVERLAPPED);
        __declspec(dllimport) unsigned long __stdcall GetCurrentProcessId(void);
        __declspec(dllimport) unsigned long __stdcall GetCurrentThreadId(void);
        __declspec(dllimport) void *__stdcall CreateFileA(const char *, unsigned long,
                                                        unsigned long,
                                                        LPSECURITY_ATTRIBUTES,
                                                        unsigned long, unsigned long,
                                                        void *);
        __declspec(dllimport) void *__stdcall CreateEventA(LPSECURITY_ATTRIBUTES, int,
                                                        int, const char *);
        __declspec(dllimport) int __stdcall CreateProcessA(
            const char *, char *, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, int,
            unsigned long, void *, const char *, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
        __declspec(dllimport) int __stdcall CloseHandle(void *);
        __declspec(dllimport) unsigned long __stdcall WaitForSingleObject(
            void *, unsigned long);
        __declspec(dllimport) int __stdcall GetExitCodeProcess(
            void *, unsigned long *lpExitCode);
        __declspec(dllimport) int __stdcall TerminateProcess(void *, unsigned int);
        __declspec(dllimport) unsigned long __stdcall WaitForMultipleObjects(
            unsigned long, void *const *, int, unsigned long);
        __declspec(dllimport) int __stdcall GetOverlappedResult(void *, LPOVERLAPPED,
                                                                unsigned long *, int);

        #if defined(_DLL)
        #define SUBPROCESS_DLLIMPORT __declspec(dllimport)
        #else
        #define SUBPROCESS_DLLIMPORT
        #endif

        #ifdef __clang__
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wreserved-identifier"
        #endif

        SUBPROCESS_DLLIMPORT int __cdecl _fileno(FILE *);
        SUBPROCESS_DLLIMPORT int __cdecl _open_osfhandle(subprocess_intptr_t, int);
        SUBPROCESS_DLLIMPORT subprocess_intptr_t __cdecl _get_osfhandle(int);

        #ifndef __MINGW32__
        void *__cdecl _alloca(subprocess_size_t);
        #else
        #include <malloc.h>
        #endif

        #ifdef __clang__
        #pragma clang diagnostic pop
        #endif

        #else
        typedef size_t subprocess_size_t;
        #endif

        #ifdef __clang__
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wpadded"
        #endif
        struct subprocess_s {
        FILE *stdin_file;
        FILE *stdout_file;
        FILE *stderr_file;

        #if defined(_WIN32)
        void *hProcess;
        void *hStdInput;
        void *hEventOutput;
        void *hEventError;
        #else
        pid_t child;
        int return_status;
        #endif

        subprocess_size_t alive;
        };
        #ifdef __clang__
        #pragma clang diagnostic pop
        #endif

        #if defined(__clang__)
        #if __has_warning("-Wunsafe-buffer-usage")
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wunsafe-buffer-usage"
        #endif
        #endif

        #if defined(_WIN32)
        subprocess_weak int subprocess_create_named_pipe_helper(void **rd, void **wr);
        int subprocess_create_named_pipe_helper(void **rd, void **wr) {
        const unsigned long pipeAccessInbound = 0x00000001;
        const unsigned long fileFlagOverlapped = 0x40000000;
        const unsigned long pipeTypeByte = 0x00000000;
        const unsigned long pipeWait = 0x00000000;
        const unsigned long genericWrite = 0x40000000;
        const unsigned long openExisting = 3;
        const unsigned long fileAttributeNormal = 0x00000080;
        const void *const invalidHandleValue =
            SUBPROCESS_PTR_CAST(void *, ~(SUBPROCESS_CAST(subprocess_intptr_t, 0)));
        struct subprocess_security_attributes_s saAttr = {sizeof(saAttr),
                                                            SUBPROCESS_NULL, 1};
        char name[256] = {0};
        static subprocess_tls long index = 0;
        const long unique = index++;

        #if defined(_MSC_VER) && _MSC_VER < 1900
        #pragma warning(push, 1)
        #pragma warning(disable : 4996)
        _snprintf(name, sizeof(name) - 1,
                    "\\\\.\\pipe\\sheredom_subprocess_h.%08lx.%08lx.%ld",
                    GetCurrentProcessId(), GetCurrentThreadId(), unique);
        #pragma warning(pop)
        #else
        snprintf(name, sizeof(name) - 1,
                "\\\\.\\pipe\\sheredom_subprocess_h.%08lx.%08lx.%ld",
                GetCurrentProcessId(), GetCurrentThreadId(), unique);
        #endif

        *rd =
            CreateNamedPipeA(name, pipeAccessInbound | fileFlagOverlapped,
                            pipeTypeByte | pipeWait, 1, 4096, 4096, SUBPROCESS_NULL,
                            SUBPROCESS_PTR_CAST(LPSECURITY_ATTRIBUTES, &saAttr));

        if (invalidHandleValue == *rd) {
            return -1;
        }

        *wr = CreateFileA(name, genericWrite, SUBPROCESS_NULL,
                            SUBPROCESS_PTR_CAST(LPSECURITY_ATTRIBUTES, &saAttr),
                            openExisting, fileAttributeNormal, SUBPROCESS_NULL);

        if (invalidHandleValue == *wr) {
            return -1;
        }

        return 0;
        }
        #endif

        int subprocess_create(const char *const commandLine[], int options,
                            struct subprocess_s *const out_process) {
        return subprocess_create_ex(commandLine, options, SUBPROCESS_NULL,
                                    out_process);
        }

        int subprocess_create_ex(const char *const commandLine[], int options,
                                const char *const environment[],
                                struct subprocess_s *const out_process) {
        #if defined(_WIN32)
        int fd;
        void *rd, *wr;
        char *commandLineCombined;
        subprocess_size_t len;
        int i, j;
        int need_quoting;
        unsigned long flags = 0;
        const unsigned long startFUseStdHandles = 0x00000100;
        const unsigned long handleFlagInherit = 0x00000001;
        const unsigned long createNoWindow = 0x08000000;
        struct subprocess_subprocess_information_s processInfo;
        struct subprocess_security_attributes_s saAttr = {sizeof(saAttr),
                                                            SUBPROCESS_NULL, 1};
        char *used_environment = SUBPROCESS_NULL;
        struct subprocess_startup_info_s startInfo = {0,
                                                        SUBPROCESS_NULL,
                                                        SUBPROCESS_NULL,
                                                        SUBPROCESS_NULL,
                                                        0,
                                                        0,
                                                        0,
                                                        0,
                                                        0,
                                                        0,
                                                        0,
                                                        0,
                                                        0,
                                                        0,
                                                        SUBPROCESS_NULL,
                                                        SUBPROCESS_NULL,
                                                        SUBPROCESS_NULL,
                                                        SUBPROCESS_NULL};

        startInfo.cb = sizeof(startInfo);
        startInfo.dwFlags = startFUseStdHandles;

        if (subprocess_option_no_window == (options & subprocess_option_no_window)) {
            flags |= createNoWindow;
        }

        if (subprocess_option_inherit_environment !=
            (options & subprocess_option_inherit_environment)) {
            if (SUBPROCESS_NULL == environment) {
            used_environment = SUBPROCESS_CONST_CAST(char *, "\0\0");
            } else {
            // We always end with two null terminators.
            len = 2;

            for (i = 0; environment[i]; i++) {
                for (j = 0; '\0' != environment[i][j]; j++) {
                len++;
                }

                // For the null terminator too.
                len++;
            }

            used_environment = SUBPROCESS_CAST(char *, _alloca(len));

            // Re-use len for the insertion position
            len = 0;

            for (i = 0; environment[i]; i++) {
                for (j = 0; '\0' != environment[i][j]; j++) {
                used_environment[len++] = environment[i][j];
                }

                used_environment[len++] = '\0';
            }

            // End with the two null terminators.
            used_environment[len++] = '\0';
            used_environment[len++] = '\0';
            }
        } else {
            if (SUBPROCESS_NULL != environment) {
            return -1;
            }
        }

        if (!CreatePipe(&rd, &wr, SUBPROCESS_PTR_CAST(LPSECURITY_ATTRIBUTES, &saAttr),
                        0)) {
            return -1;
        }

        if (!SetHandleInformation(wr, handleFlagInherit, 0)) {
            return -1;
        }

        fd = _open_osfhandle(SUBPROCESS_PTR_CAST(subprocess_intptr_t, wr), 0);

        if (-1 != fd) {
            out_process->stdin_file = _fdopen(fd, "wb");

            if (SUBPROCESS_NULL == out_process->stdin_file) {
            return -1;
            }
        }

        startInfo.hStdInput = rd;

        if (options & subprocess_option_enable_async) {
            if (subprocess_create_named_pipe_helper(&rd, &wr)) {
            return -1;
            }
        } else {
            if (!CreatePipe(&rd, &wr,
                            SUBPROCESS_PTR_CAST(LPSECURITY_ATTRIBUTES, &saAttr), 0)) {
            return -1;
            }
        }

        if (!SetHandleInformation(rd, handleFlagInherit, 0)) {
            return -1;
        }

        fd = _open_osfhandle(SUBPROCESS_PTR_CAST(subprocess_intptr_t, rd), 0);

        if (-1 != fd) {
            out_process->stdout_file = _fdopen(fd, "rb");

            if (SUBPROCESS_NULL == out_process->stdout_file) {
            return -1;
            }
        }

        startInfo.hStdOutput = wr;

        if (subprocess_option_combined_stdout_stderr ==
            (options & subprocess_option_combined_stdout_stderr)) {
            out_process->stderr_file = out_process->stdout_file;
            startInfo.hStdError = startInfo.hStdOutput;
        } else {
            if (options & subprocess_option_enable_async) {
            if (subprocess_create_named_pipe_helper(&rd, &wr)) {
                return -1;
            }
            } else {
            if (!CreatePipe(&rd, &wr,
                            SUBPROCESS_PTR_CAST(LPSECURITY_ATTRIBUTES, &saAttr), 0)) {
                return -1;
            }
            }

            if (!SetHandleInformation(rd, handleFlagInherit, 0)) {
            return -1;
            }

            fd = _open_osfhandle(SUBPROCESS_PTR_CAST(subprocess_intptr_t, rd), 0);

            if (-1 != fd) {
            out_process->stderr_file = _fdopen(fd, "rb");

            if (SUBPROCESS_NULL == out_process->stderr_file) {
                return -1;
            }
            }

            startInfo.hStdError = wr;
        }

        if (options & subprocess_option_enable_async) {
            out_process->hEventOutput =
                CreateEventA(SUBPROCESS_PTR_CAST(LPSECURITY_ATTRIBUTES, &saAttr), 1, 1,
                            SUBPROCESS_NULL);
            out_process->hEventError =
                CreateEventA(SUBPROCESS_PTR_CAST(LPSECURITY_ATTRIBUTES, &saAttr), 1, 1,
                            SUBPROCESS_NULL);
        } else {
            out_process->hEventOutput = SUBPROCESS_NULL;
            out_process->hEventError = SUBPROCESS_NULL;
        }

        // Combine commandLine together into a single string
        len = 0;
        for (i = 0; commandLine[i]; i++) {
            // for the trailing \0
            len++;

            // Quote the argument if it has a space in it
            if (strpbrk(commandLine[i], "\t\v ") != SUBPROCESS_NULL ||
                commandLine[i][0] == SUBPROCESS_NULL)
            len += 2;

            for (j = 0; '\0' != commandLine[i][j]; j++) {
            switch (commandLine[i][j]) {
            default:
                break;
            case '\\':
                if (commandLine[i][j + 1] == '"') {
                len++;
                }

                break;
            case '"':
                len++;
                break;
            }
            len++;
            }
        }

        commandLineCombined = SUBPROCESS_CAST(char *, _alloca(len));

        if (!commandLineCombined) {
            return -1;
        }

        // Gonna re-use len to store the write index into commandLineCombined
        len = 0;

        for (i = 0; commandLine[i]; i++) {
            if (0 != i) {
            commandLineCombined[len++] = ' ';
            }

            need_quoting = strpbrk(commandLine[i], "\t\v ") != SUBPROCESS_NULL ||
                        commandLine[i][0] == SUBPROCESS_NULL;
            if (need_quoting) {
            commandLineCombined[len++] = '"';
            }

            for (j = 0; '\0' != commandLine[i][j]; j++) {
            switch (commandLine[i][j]) {
            default:
                break;
            case '\\':
                if (commandLine[i][j + 1] == '"') {
                commandLineCombined[len++] = '\\';
                }

                break;
            case '"':
                commandLineCombined[len++] = '\\';
                break;
            }

            commandLineCombined[len++] = commandLine[i][j];
            }
            if (need_quoting) {
            commandLineCombined[len++] = '"';
            }
        }

        commandLineCombined[len] = '\0';

        if (!CreateProcessA(
                SUBPROCESS_NULL,
                commandLineCombined, // command line
                SUBPROCESS_NULL,     // process security attributes
                SUBPROCESS_NULL,     // primary thread security attributes
                1,                   // handles are inherited
                flags,               // creation flags
                used_environment,    // used environment
                SUBPROCESS_NULL,     // use parent's current directory
                SUBPROCESS_PTR_CAST(LPSTARTUPINFOA,
                                    &startInfo), // STARTUPINFO pointer
                SUBPROCESS_PTR_CAST(LPPROCESS_INFORMATION, &processInfo))) {
            return -1;
        }

        out_process->hProcess = processInfo.hProcess;

        out_process->hStdInput = startInfo.hStdInput;

        // We don't need the handle of the primary thread in the called process.
        CloseHandle(processInfo.hThread);

        if (SUBPROCESS_NULL != startInfo.hStdOutput) {
            CloseHandle(startInfo.hStdOutput);

            if (startInfo.hStdError != startInfo.hStdOutput) {
            CloseHandle(startInfo.hStdError);
            }
        }

        out_process->alive = 1;

        return 0;
        #else
        int stdinfd[2];
        int stdoutfd[2];
        int stderrfd[2];
        pid_t child;
        extern char **environ;
        char *const empty_environment[1] = {SUBPROCESS_NULL};
        posix_spawn_file_actions_t actions;
        char *const *used_environment;

        if (subprocess_option_inherit_environment ==
            (options & subprocess_option_inherit_environment)) {
            if (SUBPROCESS_NULL != environment) {
            return -1;
            }
        }

        if (0 != pipe(stdinfd)) {
            return -1;
        }

        if (0 != pipe(stdoutfd)) {
            return -1;
        }

        if (subprocess_option_combined_stdout_stderr !=
            (options & subprocess_option_combined_stdout_stderr)) {
            if (0 != pipe(stderrfd)) {
            return -1;
            }
        }

        if (environment) {
        #ifdef __clang__
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wcast-qual"
        #pragma clang diagnostic ignored "-Wold-style-cast"
        #endif
            used_environment = SUBPROCESS_CONST_CAST(char *const *, environment);
        #ifdef __clang__
        #pragma clang diagnostic pop
        #endif
        } else if (subprocess_option_inherit_environment ==
                    (options & subprocess_option_inherit_environment)) {
            used_environment = environ;
        } else {
            used_environment = empty_environment;
        }

        if (0 != posix_spawn_file_actions_init(&actions)) {
            return -1;
        }

        // Close the stdin write end
        if (0 != posix_spawn_file_actions_addclose(&actions, stdinfd[1])) {
            posix_spawn_file_actions_destroy(&actions);
            return -1;
        }

        // Map the read end to stdin
        if (0 !=
            posix_spawn_file_actions_adddup2(&actions, stdinfd[0], STDIN_FILENO)) {
            posix_spawn_file_actions_destroy(&actions);
            return -1;
        }

        // Close the stdout read end
        if (0 != posix_spawn_file_actions_addclose(&actions, stdoutfd[0])) {
            posix_spawn_file_actions_destroy(&actions);
            return -1;
        }

        // Map the write end to stdout
        if (0 !=
            posix_spawn_file_actions_adddup2(&actions, stdoutfd[1], STDOUT_FILENO)) {
            posix_spawn_file_actions_destroy(&actions);
            return -1;
        }

        if (subprocess_option_combined_stdout_stderr ==
            (options & subprocess_option_combined_stdout_stderr)) {
            if (0 != posix_spawn_file_actions_adddup2(&actions, STDOUT_FILENO,
                                                    STDERR_FILENO)) {
            posix_spawn_file_actions_destroy(&actions);
            return -1;
            }
        } else {
            // Close the stderr read end
            if (0 != posix_spawn_file_actions_addclose(&actions, stderrfd[0])) {
            posix_spawn_file_actions_destroy(&actions);
            return -1;
            }
            // Map the write end to stdout
            if (0 != posix_spawn_file_actions_adddup2(&actions, stderrfd[1],
                                                    STDERR_FILENO)) {
            posix_spawn_file_actions_destroy(&actions);
            return -1;
            }
        }

        #ifdef __clang__
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wcast-qual"
        #pragma clang diagnostic ignored "-Wold-style-cast"
        #endif
        if (subprocess_option_search_user_path ==
            (options & subprocess_option_search_user_path)) {
            if (0 != posix_spawnp(&child, commandLine[0], &actions, SUBPROCESS_NULL,
                                SUBPROCESS_CONST_CAST(char *const *, commandLine),
                                used_environment)) {
            posix_spawn_file_actions_destroy(&actions);
            return -1;
            }
        } else {
            if (0 != posix_spawn(&child, commandLine[0], &actions, SUBPROCESS_NULL,
                                SUBPROCESS_CONST_CAST(char *const *, commandLine),
                                used_environment)) {
            posix_spawn_file_actions_destroy(&actions);
            return -1;
            }
        }
        #ifdef __clang__
        #pragma clang diagnostic pop
        #endif

        // Close the stdin read end
        close(stdinfd[0]);
        // Store the stdin write end
        out_process->stdin_file = fdopen(stdinfd[1], "wb");

        // Close the stdout write end
        close(stdoutfd[1]);
        // Store the stdout read end
        out_process->stdout_file = fdopen(stdoutfd[0], "rb");

        if (subprocess_option_combined_stdout_stderr ==
            (options & subprocess_option_combined_stdout_stderr)) {
            out_process->stderr_file = out_process->stdout_file;
        } else {
            // Close the stderr write end
            close(stderrfd[1]);
            // Store the stderr read end
            out_process->stderr_file = fdopen(stderrfd[0], "rb");
        }

        // Store the child's pid
        out_process->child = child;

        out_process->alive = 1;

        posix_spawn_file_actions_destroy(&actions);
        return 0;
        #endif
        }

        FILE *subprocess_stdin(const struct subprocess_s *const process) {
        return process->stdin_file;
        }

        FILE *subprocess_stdout(const struct subprocess_s *const process) {
        return process->stdout_file;
        }

        FILE *subprocess_stderr(const struct subprocess_s *const process) {
        if (process->stdout_file != process->stderr_file) {
            return process->stderr_file;
        } else {
            return SUBPROCESS_NULL;
        }
        }

        int subprocess_join(struct subprocess_s *const process,
                            int *const out_return_code) {
        #if defined(_WIN32)
        const unsigned long infinite = 0xFFFFFFFF;

        if (process->stdin_file) {
            fclose(process->stdin_file);
            process->stdin_file = SUBPROCESS_NULL;
        }

        if (process->hStdInput) {
            CloseHandle(process->hStdInput);
            process->hStdInput = SUBPROCESS_NULL;
        }

        WaitForSingleObject(process->hProcess, infinite);

        if (out_return_code) {
            if (!GetExitCodeProcess(
                    process->hProcess,
                    SUBPROCESS_PTR_CAST(unsigned long *, out_return_code))) {
            return -1;
            }
        }

        process->alive = 0;

        return 0;
        #else
        int status;

        if (process->stdin_file) {
            fclose(process->stdin_file);
            process->stdin_file = SUBPROCESS_NULL;
        }

        if (process->child) {
            if (process->child != waitpid(process->child, &status, 0)) {
            return -1;
            }

            process->child = 0;

            if (WIFEXITED(status)) {
            process->return_status = WEXITSTATUS(status);
            } else {
            process->return_status = EXIT_FAILURE;
            }

            process->alive = 0;
        }

        if (out_return_code) {
            *out_return_code = process->return_status;
        }

        return 0;
        #endif
        }

        int subprocess_destroy(struct subprocess_s *const process) {
        if (process->stdin_file) {
            fclose(process->stdin_file);
            process->stdin_file = SUBPROCESS_NULL;
        }

        if (process->stdout_file) {
            fclose(process->stdout_file);

            if (process->stdout_file != process->stderr_file) {
            fclose(process->stderr_file);
            }

            process->stdout_file = SUBPROCESS_NULL;
            process->stderr_file = SUBPROCESS_NULL;
        }

        #if defined(_WIN32)
        if (process->hProcess) {
            CloseHandle(process->hProcess);
            process->hProcess = SUBPROCESS_NULL;

            if (process->hStdInput) {
            CloseHandle(process->hStdInput);
            }

            if (process->hEventOutput) {
            CloseHandle(process->hEventOutput);
            }

            if (process->hEventError) {
            CloseHandle(process->hEventError);
            }
        }
        #endif

        return 0;
        }

        int subprocess_terminate(struct subprocess_s *const process) {
        #if defined(_WIN32)
        unsigned int killed_process_exit_code;
        int success_terminate;
        int windows_call_result;

        killed_process_exit_code = 99;
        windows_call_result =
            TerminateProcess(process->hProcess, killed_process_exit_code);
        success_terminate = (windows_call_result == 0) ? 1 : 0;
        return success_terminate;
        #else
        int result;
        result = kill(process->child, 9);
        return result;
        #endif
        }

        unsigned subprocess_read_stdout(struct subprocess_s *const process,
                                        char *const buffer, unsigned size) {
        #if defined(_WIN32)
        void *handle;
        unsigned long bytes_read = 0;
        struct subprocess_overlapped_s overlapped = {0, 0, {{0, 0}}, SUBPROCESS_NULL};
        overlapped.hEvent = process->hEventOutput;

        handle = SUBPROCESS_PTR_CAST(void *,
                                    _get_osfhandle(_fileno(process->stdout_file)));

        if (!ReadFile(handle, buffer, size, &bytes_read,
                        SUBPROCESS_PTR_CAST(LPOVERLAPPED, &overlapped))) {
            const unsigned long errorIoPending = 997;
            unsigned long error = GetLastError();

            // Means we've got an async read!
            if (error == errorIoPending) {
            if (!GetOverlappedResult(handle,
                                    SUBPROCESS_PTR_CAST(LPOVERLAPPED, &overlapped),
                                    &bytes_read, 1)) {
                const unsigned long errorIoIncomplete = 996;
                const unsigned long errorHandleEOF = 38;
                error = GetLastError();

                if ((error != errorIoIncomplete) && (error != errorHandleEOF)) {
                return 0;
                }
            }
            }
        }

        return SUBPROCESS_CAST(unsigned, bytes_read);
        #else
        const int fd = fileno(process->stdout_file);
        const ssize_t bytes_read = read(fd, buffer, size);

        if (bytes_read < 0) {
            return 0;
        }

        return SUBPROCESS_CAST(unsigned, bytes_read);
        #endif
        }

        unsigned subprocess_read_stderr(struct subprocess_s *const process,
                                        char *const buffer, unsigned size) {
        #if defined(_WIN32)
        void *handle;
        unsigned long bytes_read = 0;
        struct subprocess_overlapped_s overlapped = {0, 0, {{0, 0}}, SUBPROCESS_NULL};
        overlapped.hEvent = process->hEventError;

        handle = SUBPROCESS_PTR_CAST(void *,
                                    _get_osfhandle(_fileno(process->stderr_file)));

        if (!ReadFile(handle, buffer, size, &bytes_read,
                        SUBPROCESS_PTR_CAST(LPOVERLAPPED, &overlapped))) {
            const unsigned long errorIoPending = 997;
            unsigned long error = GetLastError();

            // Means we've got an async read!
            if (error == errorIoPending) {
            if (!GetOverlappedResult(handle,
                                    SUBPROCESS_PTR_CAST(LPOVERLAPPED, &overlapped),
                                    &bytes_read, 1)) {
                const unsigned long errorIoIncomplete = 996;
                const unsigned long errorHandleEOF = 38;
                error = GetLastError();

                if ((error != errorIoIncomplete) && (error != errorHandleEOF)) {
                return 0;
                }
            }
            }
        }

        return SUBPROCESS_CAST(unsigned, bytes_read);
        #else
        const int fd = fileno(process->stderr_file);
        const ssize_t bytes_read = read(fd, buffer, size);

        if (bytes_read < 0) {
            return 0;
        }

        return SUBPROCESS_CAST(unsigned, bytes_read);
        #endif
        }

        int subprocess_alive(struct subprocess_s *const process) {
        int is_alive = SUBPROCESS_CAST(int, process->alive);

        if (!is_alive) {
            return 0;
        }
        #if defined(_WIN32)
        {
            const unsigned long zero = 0x0;
            const unsigned long wait_object_0 = 0x00000000L;

            is_alive = wait_object_0 != WaitForSingleObject(process->hProcess, zero);
        }
        #else
        {
            int status;
            is_alive = 0 == waitpid(process->child, &status, WNOHANG);

            // If the process was successfully waited on we need to cleanup now.
            if (!is_alive) {
            if (WIFEXITED(status)) {
                process->return_status = WEXITSTATUS(status);
            } else {
                process->return_status = EXIT_FAILURE;
            }

            // Since we've already successfully waited on the process, we need to wipe
            // the child now.
            process->child = 0;

            if (subprocess_join(process, SUBPROCESS_NULL)) {
                return -1;
            }
            }
        }
        #endif

        if (!is_alive) {
            process->alive = 0;
        }

        return is_alive;
        }

        #if defined(__clang__)
        #if __has_warning("-Wunsafe-buffer-usage")
        #pragma clang diagnostic pop
        #endif
        #endif

        #if defined(__cplusplus)
        } // extern "C"
        #endif

        #endif /* SHEREDOM_SUBPROCESS_H_INCLUDED */
    // END_SECTION: subprocess.h

    #ifndef JIM_IMPLEMENTATION
        #define JIM_IMPLEMENTATION
    #endif // JIM_IMPLEMENTATION
    // BEGIN_SECTION: Jim.h
        /*
        * Copyright 2021 Alexey Kutepov <reximkut@gmail.com>
        * 
        * Permission is hereby granted, free of charge, to any person obtaining
        * a copy of this software and associated documentation files (the
        * "Software"), to deal in the Software without restriction, including
        * without limitation the rights to use, copy, modify, merge, publish,
        * distribute, sublicense, and/or sell copies of the Software, and to
        * permit persons to whom the Software is furnished to do so, subject to
        * the following conditions:
        * 
        * The above copyright notice and this permission notice shall be
        * included in all copies or substantial portions of the Software.
        * 
        * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
        * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
        * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
        * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
        * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
        * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
        */
        #ifndef JIM_H_
        #define JIM_H_
        
        #ifndef JIM_SCOPES_CAPACITY
        #define JIM_SCOPES_CAPACITY 128
        #endif // JIM_SCOPES_CAPACITY
        
        typedef void* Jim_Sink;
        typedef size_t (*Jim_Write)(const void *ptr, size_t size, size_t nmemb, Jim_Sink sink);
        
        typedef enum {
            JIM_OK = 0,
            JIM_WRITE_ERROR,
            JIM_SCOPES_OVERFLOW,
            JIM_SCOPES_UNDERFLOW,
            JIM_OUT_OF_SCOPE_KEY,
            JIM_DOUBLE_KEY
        } Jim_Error;
        
        const char *jim_error_string(Jim_Error error);
        
        typedef enum {
            JIM_ARRAY_SCOPE,
            JIM_OBJECT_SCOPE,
        } Jim_Scope_Kind;
        
        typedef struct {
            Jim_Scope_Kind kind;
            int tail;
            int key;
        } Jim_Scope;
        
        typedef struct {
            Jim_Sink sink;
            Jim_Write write;
            Jim_Error error;
            Jim_Scope scopes[JIM_SCOPES_CAPACITY];
            size_t scopes_size;
        } Jim;
        
        void jim_null(Jim *jim);
        void jim_bool(Jim *jim, int boolean);
        void jim_integer(Jim *jim, long long int x);
        void jim_float(Jim *jim, double x, int precision);
        void jim_string(Jim *jim, const char *str);
        void jim_string_sized(Jim *jim, const char *str, size_t size);
        
        void jim_element_begin(Jim *jim);
        void jim_element_end(Jim *jim);
        
        void jim_array_begin(Jim *jim);
        void jim_array_end(Jim *jim);
        
        void jim_object_begin(Jim *jim);
        void jim_member_key(Jim *jim, const char *str);
        void jim_member_key_sized(Jim *jim, const char *str, size_t size);
        void jim_object_end(Jim *jim);
        
        #endif // JIM_H_
        
        #ifdef JIM_IMPLEMENTATION
        
        static size_t jim_strlen(const char *s)
        {
            size_t count = 0;
            while (*(s + count)) {
                count += 1;
            }
            return count;
        }
        
        static void jim_scope_push(Jim *jim, Jim_Scope_Kind kind)
        {
            if (jim->error == JIM_OK) {
                if (jim->scopes_size < JIM_SCOPES_CAPACITY) {
                    jim->scopes[jim->scopes_size].kind = kind;
                    jim->scopes[jim->scopes_size].tail = 0;
                    jim->scopes[jim->scopes_size].key = 0;
                    jim->scopes_size += 1;
                } else {
                    jim->error = JIM_SCOPES_OVERFLOW;
                }
            }
        }
        
        static void jim_scope_pop(Jim *jim)
        {
            if (jim->error == JIM_OK) {
                if (jim->scopes_size > 0) {
                    jim->scopes_size--;
                } else {
                    jim->error = JIM_SCOPES_UNDERFLOW;
                }
            }
        }
        
        static Jim_Scope *jim_current_scope(Jim *jim)
        {
            if (jim->error == JIM_OK) {
                if (jim->scopes_size > 0) {
                    return &jim->scopes[jim->scopes_size - 1];
                }
            }
        
            return NULL;
        }
        
        static void jim_write(Jim *jim, const char *buffer, size_t size)
        {
            if (jim->error == JIM_OK) {
                if (jim->write(buffer, 1, size, jim->sink) < size) {
                    jim->error = JIM_WRITE_ERROR;
                }
            }
        }
        
        static void jim_write_cstr(Jim *jim, const char *cstr)
        {
            if (jim->error == JIM_OK) {
                jim_write(jim, cstr, jim_strlen(cstr));
            }
        }
        
        static int jim_get_utf8_char_len(unsigned char ch)
        {
            if ((ch & 0x80) == 0) return 1;
            switch (ch & 0xf0) {
            case 0xf0:
                return 4;
            case 0xe0:
                return 3;
            default:
                return 2;
            }
        }
        
        void jim_element_begin(Jim *jim)
        {
            if (jim->error == JIM_OK) {
                Jim_Scope *scope = jim_current_scope(jim);
                if (scope && scope->tail && !scope->key) {
                    jim_write_cstr(jim, ",");
                }
            }
        }
        
        void jim_element_end(Jim *jim)
        {
            if (jim->error == JIM_OK) {
                Jim_Scope *scope = jim_current_scope(jim);
                if (scope) {
                    scope->tail = 1;
                    scope->key = 0;
                }
            }
        }
        
        const char *jim_error_string(Jim_Error error)
        {
            // TODO(#1): error strings are not particularly useful
            switch (error) {
            case JIM_OK:
                return "There is no error. The developer of this software just had a case of \"Task failed successfully\" https://i.imgur.com/Bdb3rkq.jpg - Please contact the developer and tell them that they are very lazy for not checking errors properly.";
            case JIM_WRITE_ERROR:
                return "Write error";
            case JIM_SCOPES_OVERFLOW:
                return "Stack of Scopes Overflow";
            case JIM_SCOPES_UNDERFLOW:
                return "Stack of Scopes Underflow";
            case JIM_OUT_OF_SCOPE_KEY:
                return "Out of Scope key";
            case JIM_DOUBLE_KEY:
                return "Tried to set the member key twice";
            default:
                return NULL;
            }
        }
        
        void jim_null(Jim *jim)
        {
            if (jim->error == JIM_OK) {
                jim_element_begin(jim);
                jim_write_cstr(jim, "null");
                jim_element_end(jim);
            }
        }
        
        void jim_bool(Jim *jim, int boolean)
        {
            if (jim->error == JIM_OK) {
                jim_element_begin(jim);
                if (boolean) {
                    jim_write_cstr(jim, "true");
                } else {
                    jim_write_cstr(jim, "false");
                }
                jim_element_end(jim);
            }
        }
        
        static void jim_integer_no_element(Jim *jim, long long int x)
        {
            if (jim->error == JIM_OK) {
                if (x < 0) {
                    jim_write_cstr(jim, "-");
                    x = -x;
                }
        
                if (x == 0) {
                    jim_write_cstr(jim, "0");
                } else {
                    char buffer[64];
                    size_t count = 0;
        
                    while (x > 0) {
                        buffer[count++] = (x % 10) + '0';
                        x /= 10;
                    }
        
                    for (size_t i = 0; i < count / 2; ++i) {
                        char t = buffer[i];
                        buffer[i] = buffer[count - i - 1];
                        buffer[count - i - 1] = t;
                    }
        
                    jim_write(jim, buffer, count);
                }
        
            }
        }
        
        void jim_integer(Jim *jim, long long int x)
        {
            if (jim->error == JIM_OK) {
                jim_element_begin(jim);
                jim_integer_no_element(jim, x);
                jim_element_end(jim);
            }
        }
        
        static int is_nan_or_inf(double x)
        {
            unsigned long long int mask = (1ULL << 11ULL) - 1ULL;
            return (((*(unsigned long long int*) &x) >> 52ULL) & mask) == mask;
        }
        
        void jim_float(Jim *jim, double x, int precision)
        {
            if (jim->error == JIM_OK) {
                if (is_nan_or_inf(x)) {
                    jim_null(jim);
                } else {
                    jim_element_begin(jim);
        
                    jim_integer_no_element(jim, (long long int) x);
                    x -= (double) (long long int) x;
                    while (precision-- > 0) {
                        x *= 10.0;
                    }
                    jim_write_cstr(jim, ".");
        
                    long long int y = (long long int) x;
                    if (y < 0) {
                        y = -y;
                    }
                    jim_integer_no_element(jim, y);
        
                    jim_element_end(jim);
                }
            }
        }
        
        static void jim_string_sized_no_element(Jim *jim, const char *str, size_t size)
        {
            if (jim->error == JIM_OK) {
                const char *hex_digits = "0123456789abcdef";
                const char *specials = "btnvfr";
                const char *p = str;
                size_t len = size;
        
                jim_write_cstr(jim, "\"");
                size_t cl;
                for (size_t i = 0; i < len; i++) {
                    unsigned char ch = ((unsigned char *) p)[i];
                    if (ch == '"' || ch == '\\') {
                        jim_write(jim, "\\", 1);
                        jim_write(jim, p + i, 1);
                    } else if (ch >= '\b' && ch <= '\r') {
                        jim_write(jim, "\\", 1);
                        jim_write(jim, &specials[ch - '\b'], 1);
                    } else if (0x20 <= ch && ch <= 0x7F) { // is printable
                        jim_write(jim, p + i, 1);
                    } else if ((cl = jim_get_utf8_char_len(ch)) == 1) {
                        jim_write(jim, "\\u00", 4);
                        jim_write(jim, &hex_digits[(ch >> 4) % 0xf], 1);
                        jim_write(jim, &hex_digits[ch % 0xf], 1);
                    } else {
                        jim_write(jim, p + i, cl);
                        i += cl - 1;
                    }
                }
        
                jim_write_cstr(jim, "\"");
            }
        }
        
        void jim_string_sized(Jim *jim, const char *str, size_t size)
        {
            if (jim->error == JIM_OK) {
                jim_element_begin(jim);
                jim_string_sized_no_element(jim, str, size);
                jim_element_end(jim);
            }
        }
        
        void jim_string(Jim *jim, const char *str)
        {
            if (jim->error == JIM_OK) {
                jim_string_sized(jim, str, jim_strlen(str));
            }
        }
        
        void jim_array_begin(Jim *jim)
        {
            if (jim->error == JIM_OK) {
                jim_element_begin(jim);
                jim_write_cstr(jim, "[");
                jim_scope_push(jim, JIM_ARRAY_SCOPE);
            }
        }
        
        
        void jim_array_end(Jim *jim)
        {
            if (jim->error == JIM_OK) {
                jim_write_cstr(jim, "]");
                jim_scope_pop(jim);
                jim_element_end(jim);
            }
        }
        
        void jim_object_begin(Jim *jim)
        {
            if (jim->error == JIM_OK) {
                jim_element_begin(jim);
                jim_write_cstr(jim, "{");
                jim_scope_push(jim, JIM_OBJECT_SCOPE);
            }
        }
        
        void jim_member_key(Jim *jim, const char *str)
        {
            if (jim->error == JIM_OK) {
                jim_member_key_sized(jim, str, jim_strlen(str));
            }
        }
        
        void jim_member_key_sized(Jim *jim, const char *str, size_t size)
        {
            if (jim->error == JIM_OK) {
                jim_element_begin(jim);
                Jim_Scope *scope = jim_current_scope(jim);
                if (scope && scope->kind == JIM_OBJECT_SCOPE) {
                    if (!scope->key) {
                        jim_string_sized_no_element(jim, str, size);
                        jim_write_cstr(jim, ":");
                        scope->key = 1;
                    } else {
                        jim->error = JIM_DOUBLE_KEY;
                    }
                } else {
                    jim->error = JIM_OUT_OF_SCOPE_KEY;
                }
            }
        }
        
        void jim_object_end(Jim *jim)
        {
            if (jim->error == JIM_OK) {
                jim_write_cstr(jim, "}");
                jim_scope_pop(jim);
                jim_element_end(jim);
            }
        }
        
        #endif // JIM_IMPLEMENTATION
    // END_SETION: Jim.h
// END_SECTION: External Libraries

// BEGIN_SECTION: Utilities
    bool bt__needs_quoting(const char* str) {
        for (const char* p = str; *p; p++) {
            if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '|' || *p == '&' || *p == '>' || *p == '<' || *p == '^' || *p == '"') {
                return true;
            }
        }
        return false;
    }

    char* bt_escape_argument(const char* input) {
        if (input == NULL) {
            return NULL;
        }

        bool quote = bt__needs_quoting(input);

        // Calculate the length of the escaped string
        size_t length = 0;
        for (const char* p = input; *p; p++) {
            if (*p == '\\' || *p == '"') {
                length += 2; // Escape backslashes and quotes
            } else {
                length += 1;
            }
        }

        // Add 2 for quotes if needed
        if (quote) {
            length += 2;
        }

        char* escaped = (char*)bt_arena_malloc(length + 1); // +1 for the null terminator

        // Build the escaped string
        char* dest = escaped;
        if (quote) {
            *dest++ = '"'; // Start with a quote
        }
        for (const char* p = input; *p; p++) {
            if (*p == '\\' || *p == '"') {
                *dest++ = '\\'; // Escape the character
            }
            *dest++ = *p;
        }
        if (quote) {
            *dest++ = '"'; // End with a quote
        }
        *dest = '\0'; // Null-terminate the string

        return escaped;
    }
// END_SECTION: Utilities

// BEGIN_SECTION: Platform Specific
    #ifdef BT_WINDOWS
        char *bt_win32_error_message(DWORD err) {
            static char win32ErrMsg[4*1024] = {0};
            DWORD errMsgSize = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err, LANG_USER_DEFAULT, win32ErrMsg,
                                            4*1024, NULL);

            if (errMsgSize == 0) {
                if (GetLastError() != ERROR_MR_MID_NOT_FOUND) {
                    if (sprintf(win32ErrMsg, "Could not get error message for 0x%lX", err) > 0) {
                        return (char *)&win32ErrMsg;
                    } else {
                        return NULL;
                    }
                } else {
                    if (sprintf(win32ErrMsg, "Invalid Windows Error code (0x%lX)", err) > 0) {
                        return (char *)&win32ErrMsg;
                    } else {
                        return NULL;
                    }
                }
            }

            while (errMsgSize > 1 && isspace(win32ErrMsg[errMsgSize - 1])) {
                win32ErrMsg[--errMsgSize] = '\0';
            }

            return win32ErrMsg;
        }
    #endif // BT_WINDOWS
// END_SECTION: Platofmr Specific

// BEGIN_SECTION: DA
    // Empty
// END_SECTION: DA

// BEGIN_SECTION: Log
    static Bt_Log_Level bt__min_log_level = BT_INFO;

    Bt_Log_Level bt_get_min_log_level(void) {
        return bt__min_log_level;
    }

    void bt_set_min_log_level(Bt_Log_Level min_log_level) {
        bt__min_log_level = min_log_level;
    }

    void bt_log(Bt_Log_Level level, const char *fmt, ...) {
        if (level < bt__min_log_level) return;

        FILE* stream;

        switch (level) {
        case BT_DEBUG: stream = stdout; fprintf(stream, "[DEBUG] "); break;
        case BT_INFO: stream = stdout; fprintf(stream, "[INFO] "); break;
        case BT_WARNING: stream = stderr; fprintf(stream, "[WARNING] "); break;
        case BT_ERROR: stream = stderr; fprintf(stream, "[ERROR] "); break;
        case BT_FATAL: stream = stderr; fprintf(stream, "[FATAL] "); break;
        default: BT_UNREACHABLE("bt_log");
        }

        va_list args;
        va_start(args, fmt);
        vfprintf(stream, fmt, args);
        va_end(args);
        fprintf(stream, "\n");
    }
// END_SECTION: Log

// BEGIN_SECTION: Buffer Reader/Writer
    bool bt_buffer_reader_is_empty(Bt_Buffer_Reader* br) {
        return br->buffer_size == br->offset;
    }

    char* bt_buffer_reader_extract_string(Bt_Buffer_Reader* br, uint32_t* size) {
        uint32_t str_size = bt_buffer_reader_extract_u32(br);
        if (size) {
            *size = str_size;
        }
        BT_ASSERT((br->offset + str_size <= br->buffer_size) && "not enough data to extract the string");
        const char* str = (char*)(br->buffer + br->offset);
        br->offset += str_size;

        void* ptr = bt_arena_malloc(str_size + 1);
        memcpy(ptr, str, str_size);
        ((uint8_t*)ptr)[str_size] = 0;

        return ptr;
    }

    void bt_buffer_reader_consume_string(Bt_Buffer_Reader* br) {
        uint32_t str_size = bt_buffer_reader_extract_u32(br);

        BT_ASSERT((br->offset + str_size <= br->buffer_size) && "not enough data to consume the string");
        br->offset += str_size;
    }

    #define _bt_buffer_reader_extract_create(type, true_type)                                                     \
        true_type bt_buffer_reader_extract_##type(Bt_Buffer_Reader* br) {                                         \
            BT_ASSERT((br->offset + sizeof(true_type) <= br->buffer_size) && "not enough data to extract "#type); \
            true_type value = *(true_type*)(br->buffer + br->offset);                                             \
            br->offset += sizeof(true_type);                                                                      \
            return value;                                                                                         \
        }

    #define _bt_buffer_reader_consume_create(type, true_type)                                                     \
        void bt_buffer_reader_consume_##type(Bt_Buffer_Reader* br) {                                             \
            BT_ASSERT((br->offset + sizeof(true_type) <= br->buffer_size) && "not enough data to consume "#type); \
            br->offset += sizeof(true_type);                                                                      \
        }

    _bt_buffer_reader_extract_create(u64, uint64_t)
    _bt_buffer_reader_extract_create(i64, int64_t)
    _bt_buffer_reader_extract_create(u32, uint32_t)
    _bt_buffer_reader_extract_create(i32, int32_t)
    _bt_buffer_reader_extract_create(u8, uint8_t)
    _bt_buffer_reader_extract_create(i8, int8_t)

    _bt_buffer_reader_consume_create(u64, uint64_t)
    _bt_buffer_reader_consume_create(i64, int64_t)
    _bt_buffer_reader_consume_create(u32, uint32_t)
    _bt_buffer_reader_consume_create(i32, int32_t)
    _bt_buffer_reader_consume_create(u8, uint8_t)
    _bt_buffer_reader_consume_create(i8, int8_t)

    #undef _bt_buffer_reader_extract_
    #undef _bt_buffer_reader_consume_

    void bt_buffer_writer_init(Bt_Buffer_Writer* bw, uint32_t init_size) {
        bw->buffer = (uint8_t*)bt_arena_malloc(init_size);
        bw->capacity = init_size;
        bw->size = 0;
    }

    void bt_buffer_writer_free(Bt_Buffer_Writer* bw) {
        bt_arena_free(bw->buffer);
        bw->buffer = NULL;
    }

    void bt__buffer_writer_extend_capacity(Bt_Buffer_Writer* bw, uint64_t extra) {
        if (bw->size + extra > bw->capacity) {
            uint64_t new_cap = bw->capacity*2 + bw->size + extra;
            uint8_t* temp = (uint8_t*)bt_arena_malloc(new_cap);
            memcpy(temp, bw->buffer, bw->size);
            bt_arena_free(bw->buffer);
            bw->buffer = temp;
            bw->capacity = new_cap;
        }
    }

    void bt_buffer_writer_insert_string(Bt_Buffer_Writer* bw, const char* str) {
        uint32_t size = strlen(str);
        bt__buffer_writer_extend_capacity(bw, sizeof(uint32_t) + size);
        bt_buffer_writer_insert_u32(bw, size);
        memcpy(bw->buffer + bw->size, str, size);
        bw->size += size;
    }

    #define bt__bufer_writer_insert_(type, true_type)                                \
        void bt_buffer_writer_insert_##type(Bt_Buffer_Writer* bw, true_type value) { \
            bt__buffer_writer_extend_capacity(bw, sizeof(true_type));                \
            *(true_type*)(bw->buffer + bw->size) = value;                            \
            bw->size += sizeof(true_type);                                           \
        }

    bt__bufer_writer_insert_(u64, uint64_t)
    bt__bufer_writer_insert_(i64, int64_t)
    bt__bufer_writer_insert_(u32, uint32_t)
    bt__bufer_writer_insert_(i32, int32_t)
    bt__bufer_writer_insert_(u8, uint8_t)
    bt__bufer_writer_insert_(i8, int8_t)

    #undef bt__bufer_writer_insert_
// END_SECTION: Buffer Reader/Writer

// BEGIN_SECTION: String Builder
    // Empty
// END_SECTION: String Builder

// BEGIN_SECTION: String View
    Bt_String_View bt_sv_from_sb(Bt_String_Builder* sb) {
        Bt_String_View sv;
        sv.data = sb->items;
        sv.size = sb->size;
        return sv;
    }

    Bt_String_View bt_sv_from_cstr(const char* cstr) {
        return bt_sv_from_parts(cstr, strlen(cstr));
    }

    Bt_String_View bt_sv_from_parts(const char* data, size_t size) {
        Bt_String_View sv;
        sv.data = data;
        sv.size = size;
        return sv;
    }

    Bt_String_View bt_sv_trim_left(Bt_String_View sv) {
        size_t i = 0;
        while (i < sv.size && isspace(sv.data[i])) {
            i += 1;
        }

        return bt_sv_from_parts(sv.data + i, sv.size - i);
    }

    Bt_String_View bt_sv_trim_right(Bt_String_View sv) {
        size_t i = 0;
        while (i < sv.size && isspace(sv.data[sv.size - 1 - i])) {
            i += 1;
        }

        return bt_sv_from_parts(sv.data, sv.size - i);
    }

    Bt_String_View bt_sv_trim(Bt_String_View sv) {
        return bt_sv_trim_right(bt_sv_trim_left(sv));
    }

    bool bt_sv_eq(Bt_String_View a, Bt_String_View b) {
        if (a.size != b.size) return false;
        return memcmp(a.data, b.data, a.size) == 0;
    }

    bool bt_sv_startswith(Bt_String_View sv, char* cstr) {
        size_t size = strlen(cstr);
        if (size > sv.size) return false;
        Bt_String_View a = bt_sv_from_parts(sv.data, size);
        Bt_String_View b = bt_sv_from_parts(cstr, size);
        return bt_sv_eq(a, b);
    }

    bool bt_sv_endswith(Bt_String_View sv, char *cstr) {
        size_t size = strlen(cstr);
        if (size > sv.size) return false;
        size_t ending_start = sv.size - size;
        Bt_String_View sv_ending = bt_sv_from_parts(sv.data + ending_start, size);
        return bt_sv_eq(sv_ending, bt_sv_from_cstr(cstr));
    }
// END_SECTION: String View

// BEGIN_SECTION: Arena
    // Modified version of <https://github.com/Emc2356/arena.h>
    typedef struct Arena_Page {
        char* start;
        size_t mark;
        size_t capacity;
        struct Arena_Page* prev_page;
    } Arena_Page;

    typedef struct Arena {
        size_t min_page_capacity;
        size_t mark;
        char* last_allocated_ptr;
        Arena_Page* last_page;
        Arena_Page* unused_pages;
    } Arena;

    static Arena bt__iarena = {0};

    static size_t arena__get_running_mark(Arena_Page* page) {
        size_t running_mark = 0;

        while (page) {
            running_mark += page->mark;
            page = page->prev_page;
        }

        return running_mark;
    }

    static Arena_Page* arena___new_page(size_t page_size) {
        Arena_Page* page = (Arena_Page*)malloc(sizeof(*page));
        page->start = malloc(page_size);
        page->mark = 0;
        page->capacity = page_size;
        page->prev_page = NULL;

        return page;
    }

    static void arena__add_page(Arena_Page* page, Arena_Page* in) {
        if (page->prev_page == NULL) {
            page->prev_page = in;
            return;
        }
        arena__add_page(page, in);
    }

    static void arena__free_page(Arena_Page* page) {
        if (page == NULL) {
            return;
        }
        arena__free_page(page->prev_page);
        free(page->start);
        free(page);
    }

    void bt_arena_init(size_t page_size) {
        bt__iarena.min_page_capacity = page_size;
        bt__iarena.mark = 0;
        bt__iarena.last_allocated_ptr = NULL;
        bt__iarena.last_page = arena___new_page(page_size);
        bt__iarena.unused_pages = NULL;
    }

    void bt_arena_destroy(void) {
        arena__free_page(bt__iarena.last_page);
        arena__free_page(bt__iarena.unused_pages);
    }

    size_t bt_arena_get_checkpoint(void) {
        return bt__iarena.mark;
    }

    void bt_arena_rewind(size_t checkpoint) {
        /* if it is more then the mark it is invalid and if it is equal to mark there is no work to do */
        if (checkpoint >= bt__iarena.mark) {
            return;
        }

        Arena_Page* page = bt__iarena.last_page;

        while (page) {
            size_t running_mark = arena__get_running_mark(page);

            /* if the checkpoint is between the running mark and the running mark at the start of the page */
            if (running_mark - page->mark <= checkpoint && checkpoint <= running_mark) {
                if (page == bt__iarena.last_page) { /* the checkpoint was refering to the first page */
                    bt__iarena.last_page->mark -= bt__iarena.mark - checkpoint;
                    bt__iarena.mark = checkpoint;
                    bt__iarena.last_allocated_ptr = NULL;
                    break;
                } else { /* the checkpoint refers to a page other then the first */
                    /* search for the page before the one that holds the checkpoint */
                    for (Arena_Page* other_page = bt__iarena.last_page;; other_page = other_page->prev_page) {
                        if (other_page->prev_page == page) {
                            other_page->prev_page = NULL;
                            if (bt__iarena.unused_pages == NULL) {
                                bt__iarena.unused_pages = bt__iarena.last_page;
                            } else {
                                arena__add_page(bt__iarena.unused_pages, bt__iarena.last_page);
                            }

                            break;
                        }
                    }
                    bt__iarena.last_page = page;
                    bt__iarena.last_page->mark = checkpoint - arena__get_running_mark(bt__iarena.last_page->prev_page);
                    bt__iarena.mark = checkpoint;
                    bt__iarena.last_allocated_ptr = NULL;
                    break;
                }
            }

            page = page->prev_page;
        }
    }

    void* bt_arena_malloc(size_t size) {
        /* (1) check if the size is valid */
        if (size == 0) {
            bt_log(BT_ERROR, "ARENA_INVALID_SIZE");
            abort();
            return NULL;
        }
        /* (2) provide a simple chunk */
        if (bt__iarena.last_page->mark + size <= bt__iarena.last_page->capacity) {
            bt__iarena.last_allocated_ptr = bt__iarena.last_page->start + bt__iarena.last_page->mark;
            bt__iarena.last_page->mark += size;
            bt__iarena.mark += size;
            return bt__iarena.last_page->start + bt__iarena.last_page->mark - size;
        } else { /* (3) not enough space for the chunk */
            Arena_Page* new_page = NULL;
            Arena_Page* prev_page = NULL;
            /* (4) search for an unused page with enough capacity */
            if (bt__iarena.unused_pages != NULL) {
                for (new_page = bt__iarena.unused_pages; new_page; new_page = new_page->prev_page) {
                    if (new_page->capacity >= size) {
                        if (prev_page == NULL) {
                            bt__iarena.unused_pages = new_page->prev_page;
                        } else {
                            prev_page->prev_page = new_page->prev_page;
                        }
                        break;
                    }
                    prev_page = new_page;
                }
            }

            if (new_page == NULL) {
                new_page = arena___new_page(size > bt__iarena.min_page_capacity ? size : bt__iarena.min_page_capacity);
                if (new_page == NULL) {
                    bt_log(BT_ERROR, "ARENA_OUT_OF_MEMORY");
                    abort();
                    return NULL;
                }
            }

            bt__iarena.mark = bt__iarena.mark - bt__iarena.last_page->mark + bt__iarena.last_page->capacity;
            bt__iarena.last_page->mark = bt__iarena.last_page->capacity;

            new_page->prev_page = bt__iarena.last_page;
            bt__iarena.last_page = new_page;
            new_page->mark = 0;
            /* (5) it will go to (2) so no reason to duplicate code */
            return bt_arena_malloc(size);
        }
    }

    void* bt_arena_memalign(size_t size, size_t alignment) {
        /* no alignment */
        if (alignment <= 1) {
            return bt_arena_malloc(size);
        }
        /* not power of 2 */
        if (alignment < sizeof(void*) || (alignment & (alignment - 1)) != 0) {
            bt_log(BT_ERROR, "ARENA_INVALID_ALIGNMENT");
            abort();
            return NULL;
        }
        if (size == 0) {
            bt_log(BT_ERROR, "ARENA_INVALID_SIZE");
            abort();
            return NULL;
        }

        if ((uintptr_t)bt__iarena.last_page->start + bt__iarena.last_page->mark + size <= bt__iarena.last_page->capacity) {
            if (((uintptr_t)bt__iarena.last_page->start + bt__iarena.last_page->mark) % alignment) {
                return bt_arena_malloc(size);
            }
        }
        size_t allocation_size = size + alignment - 1;
        char* address = bt_arena_malloc(allocation_size);
        address = (char*)(address + (alignment - (uintptr_t)address % alignment));

        bt__iarena.last_allocated_ptr = address;

        return address;
    }

    void* bt_arena_calloc(size_t count, size_t size) {
        void* ptr = bt_arena_malloc(count*size);

        if (ptr == NULL) {
            return NULL;
        }

        return memset(ptr, 0, count*size);
    }

    void* bt_arena_realloc(void* ptr, size_t old_size, size_t new_size) {
        size_t last_allocation_size;
        void* new_ptr;

        /* if the ptr is NULL then allocate new_size bytes */
        if (ptr == NULL) {
            return bt_arena_malloc(new_size);
        } else if (ptr != NULL && new_size == 0) {
            /* free the pointer if the new_size is 0 */
            bt_arena_free(ptr);
            return NULL;
        } else {
            /* if it was not the last allocation then it cant be extended */
            if (bt__iarena.last_allocated_ptr != ptr) {
                new_ptr = bt_arena_malloc(new_size);
                if (new_ptr == NULL) {
                    return NULL;
                }
                return memcpy(new_ptr, ptr, old_size);
            } else {
                /* ptr can be possibly extended */
                /* last_allocation_size = (start + mark) - ptr; */
                last_allocation_size = (size_t)bt__iarena.last_page->start + bt__iarena.last_page->mark - (size_t)ptr;

                /* the new size is less then the old size */
                if (last_allocation_size >= new_size) {
                    bt__iarena.last_page->mark -= last_allocation_size - new_size;
                    bt__iarena.mark -= last_allocation_size - new_size;
                    return ptr;
                } else {
                    /* check if the current page can hold extra data */
                    if (new_size - last_allocation_size + bt__iarena.last_page->mark <= bt__iarena.last_page->capacity) {
                        bt__iarena.last_page->mark += new_size - last_allocation_size;
                        bt__iarena.mark += new_size - last_allocation_size;
                        return ptr;
                    } else {
                        /* womp womp */
                        new_ptr = bt_arena_malloc(new_size);
                        if (new_ptr == NULL) {
                            return NULL;
                        }
                        return memcpy(new_ptr, ptr, old_size);
                    }
                }
            }
        }
    }

    void bt_arena_free(void* ptr) {
        /* bt__iarena.last_allocated_ptr might be null */
        if (ptr == NULL) {
            return;
        }

        /* try to reclaim the memory if it was the last allocation made */
        if (ptr == bt__iarena.last_allocated_ptr) {
            /* last_allocation_size = (start + mark) - ptr; */
            bt__iarena.mark -= (size_t)bt__iarena.last_page->start + bt__iarena.last_page->mark - (size_t)ptr;
            bt__iarena.last_page->mark -= (size_t)bt__iarena.last_page->start + bt__iarena.last_page->mark - (size_t)ptr;
            /* some safety to guard against double free */
            bt__iarena.last_allocated_ptr = NULL;
        }
    }

    char* bt_arena_strdup(const char* str) {
        size_t str_size = strlen(str);
        char* ptr = bt_arena_malloc(str_size + 1);

        if (ptr == NULL) {
            return NULL;
        }

        return memcpy(ptr, str, str_size + 1);
    }

    char* bt_arena_strndup(const char* str, size_t n) {
        size_t len = strnlen(str, n);
        char* copy = (char*)bt_arena_malloc(len + 1);
        if (copy) {
            memcpy(copy, str, len);
            copy[len] = '\0';
        }
        return copy;
    }

    void* bt_arena_memdup(const void* buffer, size_t buffer_size) {
        void* ptr = bt_arena_malloc(buffer_size);
        if (ptr == NULL) {
            return NULL;
        }
        return memcpy(ptr, buffer, buffer_size);
    }

    char* bt_arena_strcat(const char* str1, const char* str2) {
        size_t len1 = strlen(str1);
        size_t len2 = strlen(str2);
        char* result = (char*)bt_arena_malloc(len1 + len2 + 1);
        if (result) {
            memcpy(result, str1, len1);
            memcpy(result + len1, str2, len2);
            result[len1 + len2] = '\0';
        }
        return result;
    }

    char* bt_arena_cstr_from_sv(const Bt_String_View* sv) {
        char *result = bt_arena_malloc(sv->size + 1);
        memcpy(result, sv->data, sv->size);
        result[sv->size] = '\0';
        return result;
    }

    char* bt_arena__join_strings(const char* sep, const char* str1, ...) {
        va_list vargs;
        char* final_string;
        size_t final_string_len;
        size_t offset;
        const char* strarg;

        va_start(vargs, str1);
            final_string_len = 0;
            final_string_len += strlen(str1);

            strarg = va_arg(vargs, const char*);
            for (; strarg; strarg = va_arg(vargs, const char*)) {
                final_string_len += strlen(sep);
                final_string_len += strlen(strarg);
            }
        va_end(vargs);
        final_string = bt_arena_malloc(final_string_len + 1);

        if (final_string == NULL) {
            return NULL;
        }

        va_start(vargs, str1);
            offset = 0;
            memcpy(final_string + offset, str1, strlen(str1));
            offset += strlen(str1);

            strarg = va_arg(vargs, const char*);
            for (; strarg; strarg = va_arg(vargs, const char*)) {
                memcpy(final_string + offset, sep, strlen(sep));
                offset += strlen(sep);
                memcpy(final_string + offset, strarg, strlen(strarg));
                offset += strlen(strarg);
            }
        va_end(vargs);

        final_string[final_string_len] = 0;

        return final_string;
    }

    char* bt_arena_sprintf(const char* format, ...) {
        va_list args;
        char* result;
        int n;

        va_start(args, format);
        n = vsnprintf(NULL, 0, format, args);
        va_end(args);

        if (n < 0) {
            bt_log(BT_ERROR, "ARENA_INVALID_FORMAT");
            abort();
        }

        result = (char*)bt_arena_malloc(n + 1);
        if (result == NULL) {
            return NULL;
        }
        va_start(args, format);
        vsnprintf(result, n + 1, format, args);
        va_end(args);

        return result;
    }
// END_SECTION: Arena

// BEGIN_SECTION: Time
    void bt_sleep(size_t ms) {
        #ifdef BT_WINDOWS
            Sleep(ms);
        #else // BT_WINDOWS
            struct timespec ts;
            ts.tv_sec = ms / 1000;
            ts.tv_nsec = (ms % 1000) * 1000000;
            nanosleep(&ts, NULL);
        #endif // BT_WINDOWS
    }

    // Taken from CPython source
    #if !defined(BT_WINDOWS)
    static inline int bt__int64_t_safe_mul_check_overflow(int64_t a, int64_t b) {
        return ((a < INT64_MIN / b) || (INT64_MAX / b < a));
    }

    // Taken from CPython source
    static inline int bt__int64_t_safe_mul(int64_t *t, int64_t k) {
        if (bt__int64_t_safe_mul_check_overflow(*t, k)) {
            *t = (*t >= 0) ? INT64_MAX : INT64_MIN;
            return -1;
        }
        else {
            *t *= k;
            return 0;
        }
    }

    // Taken from CPython source
    // Compute t1 + t2. Clamp to [INT64_MIN; INT64_MAX] on overflow.
    static inline int bt__int64_t_safe_add(int64_t *t1, int64_t t2) {
        if (t2 > 0 && *t1 > INT64_MAX - t2) {
            *t1 = INT64_MAX;
            return 0;
        }
        else if (t2 < 0 && *t1 < INT64_MIN - t2) {
            *t1 = INT64_MIN;
            return 0;
        }
        *t1 += t2;
        return 1;
    }

    // Taken from CPython source
    static int bt__extract_time_from_timespec(int64_t* tp, const struct timespec* ts) {
        int64_t t, tv_nsec;
        t = (int64_t)ts->tv_sec;

        int res1 = bt__int64_t_safe_mul(&t, 1000 * 1000 * 1000);

        tv_nsec = ts->tv_nsec;
        int res2 = bt__int64_t_safe_add(&t, tv_nsec);
        *tp = t;

        if (res1 < 0 || res2 < 0) {
            return 0;
        }
        return 1;
    }
    #endif // !defined(BT_WINDOWS)

    // Taken from CPython source
    bool bt_time_perf_counter(int64_t *tp) {
        #ifdef BT_WINDOWS
            FILETIME system_time;
            ULARGE_INTEGER large;

            GetSystemTimePreciseAsFileTime(&system_time);
            large.u.LowPart = system_time.dwLowDateTime;
            large.u.HighPart = system_time.dwHighDateTime;
            /* 11,644,473,600,000,000,000: number of nanoseconds between
            the 1st january 1601 and the 1st january 1970 (369 years + 89 leap
            days). */
            int64_t ns = large.QuadPart * 100 - 11644473600000000000LLU;
            *tp = ns;

        #else   /* BT_WINDOWS */
            struct timespec ts;

            if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
                bt_log(BT_ERROR, "clock_gettime failed: %s", strerror(errno));
                return false;
            }
            if (!bt__extract_time_from_timespec(tp, &ts)) {
                return false;
            }

        #endif   /* !BT_WINDOWS */
        return true;
    }
// END_SECTION: Time

// BEGIN_SECTION: Command
    void bt__cmd_add_many(Bt_Cmd* cmd, ...) {
        va_list vargs;
        const char* strarg;

        va_start(vargs, cmd);

        for (strarg = va_arg(vargs, const char*); strarg; strarg = va_arg(vargs, const char*)) {
            bt_cmd_append(cmd, strarg);
        }
        va_end(vargs);
    }

    bool bt_execute_cmd(const Bt_Cmd* cmd, int* returncode, const char* cwd) {
        if (cmd->size < 1) {
            bt_log(BT_ERROR, "Could not run empty command");
            return false;
        }
        #ifdef _WIN32
            Bt_String_Builder sb = {0};

            STARTUPINFO siStartInfo;
            ZeroMemory(&siStartInfo, sizeof(siStartInfo));
            siStartInfo.cb = sizeof(STARTUPINFO);
            // NOTE: theoretically setting NULL to std handles should not be a problem
            // https://docs.microsoft.com/en-us/windows/console/getstdhandle?redirectedfrom=MSDN#attachdetach-behavior
            // TODO: check for errors in GetStdHandle
            siStartInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);
            siStartInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
            siStartInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
            siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

            PROCESS_INFORMATION piProcInfo;
            ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

            for (size_t i = 0; i < cmd->size; ++i) {
                const char *arg = cmd->items[i];
                if (arg == NULL) break;
                if (i > 0) bt_sb_append_cstr(&sb, " ");
                if (!strchr(arg, ' ')) {
                    bt_sb_append_cstr(&sb, arg);
                } else {
                    bt_da_append(&sb, '\'');
                    bt_sb_append_cstr(&sb, arg);
                    bt_da_append(&sb, '\'');
                }
            }

            bt_sb_append_null(&sb);
            BOOL bSuccess = CreateProcessA(NULL, sb.items, NULL, NULL, TRUE, 0, NULL, cwd, &siStartInfo, &piProcInfo);
            bt_sb_free(&sb);

            if (!bSuccess) {
                bt_log(BT_ERROR, "Could not create child process: %s", bt_win32_error_message(GetLastError()));
                return false;
            }

            CloseHandle(piProcInfo.hThread);

            DWORD result = WaitForSingleObject(
                                piProcInfo.hProcess,    // HANDLE hHandle,
                                INFINITE                // DWORD  dwMilliseconds
                        );

            if (result == WAIT_FAILED) {
                bt_log(BT_ERROR, "could not wait on child process: %s", bt_win32_error_message(GetLastError()));
                return false;
            }

            if (returncode) {
                DWORD exit_status;
                if (!GetExitCodeProcess(piProcInfo.hProcess, &exit_status)) {
                    bt_log(BT_ERROR, "could not get process exit code: %s", bt_win32_error_message(GetLastError()));
                    return false;
                }
                *returncode = exit_status;
            }

            CloseHandle(piProcInfo.hProcess);

            return true;
        #else
        char* old_cwd = NULL;

            // Save the current working directory if a new one is provided
            if (cwd != NULL) {
                size_t old_cwd_size = 8;
                old_cwd = (char*)malloc(old_cwd_size * sizeof(char));

                while (getcwd(old_cwd, old_cwd_size) == NULL) {
                    if (errno == ERANGE) {
                        old_cwd_size *= 2;
                        free(old_cwd);
                        old_cwd = (char*)malloc(old_cwd_size * sizeof(char));
                    } else {
                        bt_log(BT_ERROR, "getcwd failed: %s", strerror(errno));
                        return false;
                    }
                }
                if (chdir(cwd) != 0) {
                    bt_log(BT_ERROR, "chdir failed for `%s`: %s", cwd, strerror(errno));
                    free(old_cwd);
                    return false;
                }
            }

            pid_t cpid = fork();
            if (cpid < 0) {
                bt_log(BT_ERROR, "Could not fork child process: %s", strerror(errno));
                if (old_cwd != NULL) {
                    if (chdir(old_cwd) != 0) {
                        bt_log(BT_ERROR, "chdir failed for `%s`: %s", old_cwd, strerror(errno));
                        free(old_cwd);
                        return false;
                    }
                    free(old_cwd);
                }
                return false;
            }

            if (cpid == 0) {
                // NOTE: This leaks a bit of memory in the child process.
                // But do we actually care? It's a one off leak anyway...
                Bt_Cmd cmd_null = {0};
                bt_cmd_extend(&cmd_null, cmd);
                bt_cmd_append(&cmd_null, NULL);

                if (execvp(cmd->items[0], (char * const*) cmd_null.items) < 0) {
                    bt_log(BT_ERROR, "Could not exec child process: %s", strerror(errno));
                    if (old_cwd != NULL) {
                        if (chdir(old_cwd) != 0) {
                            bt_log(BT_ERROR, "chdir failed for `%s`: %s", old_cwd, strerror(errno));
                            free(old_cwd);
                            return false;
                        }
                        free(old_cwd);
                    }
                    return false;
                }
                BT_UNREACHABLE("bt_cmd_run_async");
            }

            for (;;) {
                int wstatus = 0;
                if (waitpid(cpid, &wstatus, 0) < 0) {
                    bt_log(BT_ERROR, "could not wait on command (pid %d): %s", cpid, strerror(errno));
                    if (old_cwd != NULL) {
                        if (chdir(old_cwd) != 0) {
                            bt_log(BT_ERROR, "chdir failed for `%s`: %s", old_cwd, strerror(errno));
                            free(old_cwd);
                            return false;
                        }
                        free(old_cwd);
                    }
                    return false;
                }

                if (WIFEXITED(wstatus)) {
                    if (returncode) {
                        *returncode = WEXITSTATUS(wstatus);
                    }
                    break;
                }

                if (WIFSIGNALED(wstatus)) {
                    bt_log(BT_ERROR, "command process was terminated by %s", strsignal(WTERMSIG(wstatus)));
                    if (old_cwd != NULL) {
                        if (chdir(old_cwd) != 0) {
                            bt_log(BT_ERROR, "chdir failed for `%s`: %s", old_cwd, strerror(errno));
                            free(old_cwd);
                            return false;
                        }
                        free(old_cwd);
                    }
                    return false;
                }
            }

            if (old_cwd != NULL) {
                if (chdir(old_cwd) != 0) {
                    bt_log(BT_ERROR, "chdir failed for `%s`: %s", old_cwd, strerror(errno));
                    free(old_cwd);
                    return false;
                }
                free(old_cwd);
            }
            return true;
        #endif
    }

    bool bt__execute_command(int* returncode, const char* cwd, ...) {
        Bt_Cmd cmd = {0};

        va_list args;

        va_start(args, cwd);

        const char* arg = va_arg(args, const char*);
        for (; arg; arg = va_arg(args, const char*)) {
            bt_cmd_append(&cmd, bt_arena_strdup(arg));
        }

        return bt_execute_cmd(&cmd, returncode, cwd);
    }

    Bt_Process* bt_process_start(Bt_Cmd* cmd) {
        BT_ASSERT(cmd->size && "the command must have at least one argument");
        bt_cmd_append(cmd, NULL);
        cmd->size -= 1;
        struct subprocess_s* process = bt_arena_malloc(sizeof(*process));
        int options = subprocess_option_combined_stdout_stderr |
                        subprocess_option_inherit_environment |
                        subprocess_option_enable_async |
                        subprocess_option_no_window |
                        subprocess_option_search_user_path;
        if (subprocess_create((const char* const*)cmd->items, options, process) < 0) {
            return NULL;
        }

        return (Bt_Process*)process;
    }

    bool bt_process_kill(Bt_Process* process) {
        return !subprocess_terminate((struct subprocess_s*)process);
    }

    bool bt_process_destroy(Bt_Process* process) {
        return subprocess_destroy((struct subprocess_s*)process);
    }

    bool bt_process_is_alive(Bt_Process* process) {
        return subprocess_alive((struct subprocess_s*)process);
    }

    bool bt_process_wait_for_completion(Bt_Process* process, int* returncode) {
        return !subprocess_join((struct subprocess_s*)process, returncode);
    }

    bool bt_process_get_return_code(Bt_Process* process, int* returncode) {
        return !subprocess_join((struct subprocess_s*)process, returncode);
    }

    int bt_process_read_output(Bt_Process* process, void* buffer, size_t buffer_size) {
        return subprocess_read_stdout((struct subprocess_s*)process, buffer, buffer_size);
    }
    
    void bt__delete_n_lines(int n) {
        if (n <= 0) return;
    
        #ifdef _WIN32
            // Windows implementation
            HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
            if (hStdout == INVALID_HANDLE_VALUE) {
                fprintf(stderr, "Error getting handle to stdout\n");
                return;
            }
        
            CONSOLE_SCREEN_BUFFER_INFO csbi;
            if (!GetConsoleScreenBufferInfo(hStdout, &csbi)) {
                fprintf(stderr, "Error getting console screen buffer info\n");
                return;
            }
        
            COORD cursorPosition = csbi.dwCursorPosition;
            cursorPosition.Y -= n;
            if (cursorPosition.Y < 0) cursorPosition.Y = 0;
        
            if (!SetConsoleCursorPosition(hStdout, cursorPosition)) {
                fprintf(stderr, "Error setting cursor position\n");
                return;
            }
        
            // Clear lines by overwriting with spaces
            DWORD written;
            FillConsoleOutputCharacter(hStdout, ' ', csbi.dwSize.X * n, cursorPosition, &written);
            FillConsoleOutputAttribute(hStdout, csbi.wAttributes, csbi.dwSize.X * n, cursorPosition, &written);
        #else
            // Linux/Unix implementation using ANSI escape codes
            for (int i = 0; i < n; i++) {
                printf("\033[1A"); // Move cursor up one line
                printf("\033[K");  // Clear the line
            }
        #endif
    }

    bool bt_execute_command_queue(Bt_Cmds* command_queue, size_t command_queue_size, size_t max_active_processes) {
        size_t command_count = 0;
        for (size_t i = 0; i < command_queue_size; i++) {
            command_count += command_queue[i].size;
        }

        if (command_count == 0) {
            return true;
        }

        // seams like overkill that you would ever have a 16mb error
        size_t reading_buffer_capacity = 16 * 1024 * 1024;
        char* reading_buffer = malloc(reading_buffer_capacity);

        size_t commands_completed = 0;

        for (size_t i = 0; i < command_queue_size; i++) {
            Bt_Cmds current_commands_to_execute = command_queue[i];
            if (current_commands_to_execute.size <= 0) {
                continue;
            }

            Bt_Cmds active_commands = {0};

            size_t lines_to_clear = 0;
            Bt_String_Array permenant_lines_to_add = {0};
            bool needs_to_update_terminal = false;
            bool failed = false;

            bool processing = true;
            while (processing) {
                for (size_t j = active_commands.size; j > 0; j--) {
                    // stupid ass size_t
                    j--;
                    if (j == (0ul-1)) {
                        break;
                    }

                    Bt_Cmd active_command = active_commands.items[j];

                    BT_ASSERT(active_command.process);
                    if (!bt_process_is_alive(active_command.process)) {
                        needs_to_update_terminal = true;
                        int returncode;
                        BT_ASSERT(bt_process_get_return_code(active_command.process, &returncode) && "Failed to get the return code of the process");

                        size_t bytes_read = bt_process_read_output(active_command.process, reading_buffer, reading_buffer_capacity);

                        if (bytes_read > 0) {
                            bt_da_append(&permenant_lines_to_add, bt_arena_sprintf("[INFO] %s\n", active_command.message));
                            bt_da_append(&permenant_lines_to_add, bt_arena_strdup(reading_buffer));
                        }

                        if (returncode != 0) {
                            for (size_t k = 0; k < j; k++) {
                                if (bt_process_is_alive(active_commands.items[k].process)) {
                                    bt_process_destroy(active_commands.items[k].process);
                                }
                            }

                            bt__delete_n_lines(lines_to_clear);
                            const char* line;
                            size_t k;
                            bt_da_foreach(k, line, &permenant_lines_to_add) {
                                printf("%s", line);
                            }
                            bt_log(BT_ERROR, "%s", active_command.fail_message);
                            free(reading_buffer);
                            return false;
                        }

                        bt_process_destroy(active_command.process);
                        bt_da_popi(&active_commands, j);
                        commands_completed += 1;
                    }

                    // stupid ass size_t
                    j++;
                }

                while (active_commands.size < max_active_processes && command_queue[i].size > 0) {
                    Bt_Cmd new_command = command_queue[i].items[0];
                    bt_da_popi(&command_queue[i], 0);

                    bt_da_append(&new_command, NULL);
                    new_command.size -= 1;

                    new_command.process = bt_process_start(&new_command);

                    if (new_command.process == NULL) {
                        Bt_String_Builder sb = {0};
                        bt_sb_append_cstr(&sb, new_command.items[0]);
                        for (size_t m = 1; m < new_command.size; m++) {
                            bt_sb_append_char(&sb, ' ');
                            bt_sb_append_cstr(&sb, new_command.items[m]);
                        }
                        bt_sb_append_null(&sb);
                        bt_log(BT_ERROR, "failed to start command `%s`", bt_sb_as_cstr(&sb));
                    }

                    bt_da_append(&active_commands, new_command);
                    needs_to_update_terminal = true;
                }

                if (needs_to_update_terminal) {
                    size_t k;
                    bt__delete_n_lines(lines_to_clear);
                    const char* line;
                    bt_da_foreach(k, line, &permenant_lines_to_add) {
                        printf("%s", line);
                    }
                    permenant_lines_to_add.size = 0;

                    Bt_Cmd* active_process_p;

                    bt_da_foreach_ref(k, active_process_p, &active_commands) {
                        printf("[%zu/%zu] %s\n", commands_completed + 1 + k, command_count, active_process_p->message);
                    }

                    lines_to_clear = active_commands.size;

                    needs_to_update_terminal = false;
                }

                if (active_commands.size == 0) {
                    processing = false;
                }

                // check 20 times per second
                bt_sleep(1000 / 20);
            }

            bt_da_free(&active_commands);
            bt_da_free(&permenant_lines_to_add);

            if (failed) {
                free(reading_buffer);
                return false;
            }
        }

        free(reading_buffer);
        fflush(stdout);

        return true;
    }
// END_SECTION: Command

// BEGIN_SECTION: Compiler
    // BEGIN_SECTION: Clang
        typedef struct Bt__clang_compiler_extra_data {
            Bt_String_Array base_archive_command;
        } Bt__clang_compiler_extra_data;

        void bt_clang_compiler_change_archive_command(Bt_Compiler* compiler, Bt_Cmd* command) {
            Bt__clang_compiler_extra_data* extra_data = (Bt__clang_compiler_extra_data*)compiler->extra_data;

            extra_data->base_archive_command.size = 0;
            bt_cmd_extend(&extra_data->base_archive_command, command);
        }

        void bt__clang_compiler_generate_static_library(struct Bt_Compiler* compiler, Bt_Cmd* cmd, Bt_String_Array* files, const char* output_location, const char* name) {
            (void) compiler;
            Bt__clang_compiler_extra_data* extra_data = (Bt__clang_compiler_extra_data*)compiler->extra_data;

            bt_cmd_extend(cmd, &extra_data->base_archive_command);
            bt_cmd_append(cmd, bt_concat_paths(output_location, bt_arena_sprintf("lib%s.a", name)));

            bt_cmd_extend(cmd, files);
        }

        const char* bt__clang_compiler_get_static_library_name(struct Bt_Compiler* compiler, const char* name, const char* output_location) {
            return bt_concat_paths(output_location, bt_arena_sprintf("lib%s.a", name));
        }

        void bt__clang_compiler_change_c_compiler_name(struct Bt_Compiler* compiler, const char* c_compiler) {
            compiler->base_c_compile_command.items[0] = c_compiler;
        }

        void bt__clang_compiler_change_cxx_compiler_name(struct Bt_Compiler* compiler, const char* cpp_compiler) {
            compiler->base_cxx_compile_command.items[0] = cpp_compiler;
        }

        void bt__clang_compiler_change_linker_command_name(struct Bt_Compiler* compiler, const char* linker) {
            compiler->base_linker_command.items[0] = linker;
        }

        void bt__clang_compiler_add_include_directory(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const char* directory) {
            (void) compiler;
            bt_cmd_add_many(cmd, "-I", directory);
        }

        void bt__clang_compiler_add_include_directories(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const Bt_String_Array* directories) {
            (void) compiler;
            for (size_t i = 0; i < directories->size; i++) {
                bt_cmd_add_many(cmd, "-I", directories->items[i]);
            }
        }

        void bt__clang_compiler_add_library_directory(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const char* directory) {
            (void) compiler;
            bt_cmd_add_many(cmd, "-L", directory);
        }

        void bt__clang_compiler_add_library_directories(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const Bt_String_Array* directories) {
            (void) compiler;
            size_t i;
            const char* directory;
            bt_da_foreach(i, directory, directories) {
                bt_cmd_add_many(cmd, "-L", directory);
            }
        }

        void bt__clang_compiler_add_library(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const char* library_name) {
            (void) compiler;
            bt_cmd_add_many(cmd, "-l", library_name);
        }

        void bt__clang_compiler_add_libraries(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const Bt_String_Array* library_names) {
            (void) compiler;
            size_t i;
            const char* library_name;
            bt_da_foreach(i, library_name, library_names) {
                bt_cmd_add_many(cmd, "-l", library_name);
            }
        }

        void bt__clang_compiler_add_define(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const char* define_name, const char* define_value) {
            (void) compiler;
            bt_cmd_append(cmd, "-D");
            if (define_value) {
                bt_cmd_append(cmd, bt_arena_sprintf("%s=%s", define_name, define_value));
            } else {
                bt_cmd_append(cmd, define_name);
            }
        }

        void bt__clang_compiler_add_source_file(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const char* source_file) {
            (void) compiler;
            bt_cmd_append(cmd, source_file);
        }

        void bt__clang_compiler_add_source_files(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const Bt_String_Array* source_files) {
            (void) compiler;
            bt_cmd_extend(cmd, source_files);
        }

        void bt__clang_add_file_to_linker(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const char* source_file) {
            (void) compiler;
            bt_cmd_append(cmd, source_file);
        }

        void bt__clang_add_files_to_linker(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const Bt_String_Array* source_files) {
            (void) compiler;
            bt_cmd_extend(cmd, source_files);
        }

        void bt__clang_compiler_specify_output_name(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const char* output_name) {
            (void) compiler;
            bt_cmd_add_many(cmd, "-o", output_name);
        }

        void bt__clang_compiler_no_linking(struct Bt_Compiler* compiler, Bt_Cmd* cmd) {
            (void) compiler;
            bt_cmd_append(cmd, "-c");
        }

        void bt__clang_compiler_add_precompiled_header(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const char* filename) {
            (void) compiler;
            bt_cmd_add_many(cmd, "-include-pch", bt_arena_sprintf("%s.pch", filename));
        }

        void bt__clang_compiler_add_precompiled_headers(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const Bt_String_Array* filenames) {
            (void) compiler;
            size_t i;
            const char* filename;
            bt_da_foreach(i, filename, filenames) {
                bt_cmd_add_many(cmd, "-include-pch", bt_arena_sprintf("%s.pch", filename));
            }
        }

        void bt__clang_compiler_turn_on_optimizations(struct Bt_Compiler* compiler, Bt_Cmd* cmd) {
            (void) compiler;
            bt_cmd_append(cmd, "-O3");
        }

        void bt__clang_compiler_enable_all_warnings(struct Bt_Compiler* compiler, Bt_Cmd* cmd) {
            (void) compiler;
            bt_cmd_add_many(cmd, "-Wall", "-Wextra");
        }

        void bt__clang_compiler_treat_warnings_as_errors(struct Bt_Compiler* compiler, Bt_Cmd* cmd) {
            (void) compiler;
            bt_cmd_append(cmd, "-Werror");
        }

        void bt__clang_compiler_generate_debug_symbols(struct Bt_Compiler* compiler, Bt_Cmd* cmd) {
            (void) compiler;
            bt_cmd_append(cmd, "-g3");
        }

        char* bt__clang_compiler_source_file_to_object_filename(struct Bt_Compiler* compiler, const char* build_directory, const char* filename) {
            (void) compiler;

            return bt_concat_paths(build_directory, bt_arena_sprintf("%s.o", filename));
        }

        char* bt__clang_compiler_source_file_to_precompiled_header_filename(struct Bt_Compiler* compiler, const char* filename) {
            (void) compiler;

            return bt_arena_sprintf("%s.pch", filename);
        }

        Bt_Compiler* bt_create_clang_compiler(char* c_standard, char* cxx_standard) {
            Bt_Compiler* compiler = bt_arena_malloc(sizeof(*compiler));
            memset(compiler, 0, sizeof(*compiler));

            compiler->name = "clang";

        #ifdef BT_WINDOWS
            compiler->executable_extension = ".exe";
        #else // BT_WINDOWS
            compiler->executable_extension = ".out";
        #endif // BT_WINDOWS

            bt_cmd_append(&compiler->base_c_compile_command, "clang");
            bt_cmd_append(&compiler->base_cxx_compile_command, "clang++");
            bt_cmd_append(&compiler->base_linker_command, "clang++");

            if (c_standard) {
                bt_cmd_append(&compiler->base_c_compile_command, bt_arena_sprintf("-std=%s", c_standard));
            }
            if (cxx_standard) {
                bt_cmd_append(&compiler->base_cxx_compile_command, bt_arena_sprintf("-std=%s", cxx_standard));
            }

            compiler->generate_static_library = bt__clang_compiler_generate_static_library;
            compiler->get_static_library_name = bt__clang_compiler_get_static_library_name;
            compiler->change_c_compiler_name = bt__clang_compiler_change_c_compiler_name;
            compiler->change_cxx_compiler_name = bt__clang_compiler_change_cxx_compiler_name;
            compiler->change_linker_command_name = bt__clang_compiler_change_linker_command_name;
            compiler->add_include_directory = bt__clang_compiler_add_include_directory;
            compiler->add_include_directories = bt__clang_compiler_add_include_directories;
            compiler->add_library_directory = bt__clang_compiler_add_library_directory;
            compiler->add_library_directories = bt__clang_compiler_add_library_directories;
            compiler->add_library = bt__clang_compiler_add_library;
            compiler->add_libraries = bt__clang_compiler_add_libraries;
            compiler->add_define = bt__clang_compiler_add_define;
            compiler->add_source_file = bt__clang_compiler_add_source_file;
            compiler->add_source_files = bt__clang_compiler_add_source_files;
            compiler->add_file_to_linker = bt__clang_add_file_to_linker;
            compiler->add_files_to_linker = bt__clang_add_files_to_linker;
            compiler->specify_output_name = bt__clang_compiler_specify_output_name;
            compiler->no_linking = bt__clang_compiler_no_linking;
            compiler->add_precompiled_header = bt__clang_compiler_add_precompiled_header;
            compiler->add_precompiled_headers = bt__clang_compiler_add_precompiled_headers;
            compiler->turn_on_optimizations = bt__clang_compiler_turn_on_optimizations;
            compiler->enable_all_warnings = bt__clang_compiler_enable_all_warnings;
            compiler->treat_warnings_as_errors = bt__clang_compiler_treat_warnings_as_errors;
            compiler->generate_debug_symbols = bt__clang_compiler_generate_debug_symbols;
            compiler->source_file_to_object_filename = bt__clang_compiler_source_file_to_object_filename;
            compiler->source_file_to_precompiled_header_filename = bt__clang_compiler_source_file_to_precompiled_header_filename;

            Bt__clang_compiler_extra_data* extra_data = bt_arena_malloc(sizeof(*extra_data));
            memset(extra_data, 0, sizeof(*extra_data));
            bt_cmd_append(&extra_data->base_archive_command, "ar");
            bt_cmd_append(&extra_data->base_archive_command, "rcs");
            bt_cmd_append(&extra_data->base_archive_command, "-o");

            compiler->extra_data = extra_data;

            return compiler;
        }

        void bt_destroy_clang_compiler(Bt_Compiler* clang_compiler) {
            bt_cmd_free(&clang_compiler->base_c_compile_command);
            bt_cmd_free(&clang_compiler->base_cxx_compile_command);
            bt_cmd_free(&clang_compiler->base_linker_command);

            Bt__clang_compiler_extra_data* extra_data = (Bt__clang_compiler_extra_data*)clang_compiler->extra_data;
            bt_cmd_free(&extra_data->base_archive_command);
            bt_arena_free(extra_data);

            bt_arena_free(clang_compiler);
        }
    // END_SECTION: Clang

    // BEGIN_SECTION: Gnu
        typedef struct Bt__gnu_compiler_extra_data {
            Bt_String_Array base_archive_command;
        } Bt__gnu_compiler_extra_data;

        void bt_gnu_compiler_change_archive_command(Bt_Compiler* compiler, Bt_Cmd* command) {
            Bt__gnu_compiler_extra_data* extra_data = (Bt__gnu_compiler_extra_data*)compiler->extra_data;

            extra_data->base_archive_command.size = 0;
            bt_cmd_extend(&extra_data->base_archive_command, command);
        }

        void bt__gnu_compiler_generate_static_library(struct Bt_Compiler* compiler, Bt_Cmd* cmd, Bt_String_Array* files, const char* output_location, const char* name) {
            (void) compiler;
            Bt__gnu_compiler_extra_data* extra_data = (Bt__gnu_compiler_extra_data*)compiler->extra_data;

            bt_cmd_extend(cmd, &extra_data->base_archive_command);
            bt_cmd_append(cmd, bt_concat_paths(output_location, bt_arena_sprintf("lib%s.a", name)));

            bt_cmd_extend(cmd, files);
        }

        const char* bt__gnu_compiler_get_static_library_name(struct Bt_Compiler* compiler, const char* name, const char* output_location) {
            return bt_concat_paths(output_location, bt_arena_sprintf("lib%s.a", name));
        }

        void bt__gnu_compiler_change_c_compiler_name(struct Bt_Compiler* compiler, const char* c_compiler) {
            compiler->base_c_compile_command.items[0] = c_compiler;
        }

        void bt__gnu_compiler_change_cxx_compiler_name(struct Bt_Compiler* compiler, const char* cpp_compiler) {
            compiler->base_cxx_compile_command.items[0] = cpp_compiler;
        }

        void bt__gnu_compiler_change_linker_command_name(struct Bt_Compiler* compiler, const char* linker) {
            compiler->base_linker_command.items[0] = linker;
        }

        void bt__gnu_compiler_add_include_directory(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const char* directory) {
            (void) compiler;
            bt_cmd_add_many(cmd, "-I", directory);
        }

        void bt__gnu_compiler_add_include_directories(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const Bt_String_Array* directories) {
            (void) compiler;
            for (size_t i = 0; i < directories->size; i++) {
                bt_cmd_add_many(cmd, "-I", directories->items[i]);
            }
        }

        void bt__gnu_compiler_add_library_directory(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const char* directory) {
            (void) compiler;
            bt_cmd_add_many(cmd, "-L", directory);
        }

        void bt__gnu_compiler_add_library_directories(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const Bt_String_Array* directories) {
            (void) compiler;
            size_t i;
            const char* directory;
            bt_da_foreach(i, directory, directories) {
                bt_cmd_add_many(cmd, "-L", directory);
            }
        }

        void bt__gnu_compiler_add_library(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const char* library_name) {
            (void) compiler;
            bt_cmd_add_many(cmd, "-l", library_name);
        }

        void bt__gnu_compiler_add_libraries(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const Bt_String_Array* library_names) {
            (void) compiler;
            size_t i;
            const char* library_name;
            bt_da_foreach(i, library_name, library_names) {
                bt_cmd_add_many(cmd, "-l", library_name);
            }
        }

        void bt__gnu_compiler_add_define(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const char* define_name, const char* define_value) {
            (void) compiler;
            bt_cmd_append(cmd, "-D");
            if (define_value) {
                bt_cmd_append(cmd, bt_arena_sprintf("%s=%s", define_name, define_value));
            } else {
                bt_cmd_append(cmd, define_name);
            }
        }

        void bt__gnu_compiler_add_source_file(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const char* source_file) {
            (void) compiler;
            bt_cmd_append(cmd, source_file);
        }

        void bt__gnu_compiler_add_source_files(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const Bt_String_Array* source_files) {
            (void) compiler;
            bt_cmd_extend(cmd, source_files);
        }

        void bt__gnu_add_file_to_linker(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const char* source_file) {
            (void) compiler;
            bt_cmd_append(cmd, source_file);
        }

        void bt__gnu_add_files_to_linker(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const Bt_String_Array* source_files) {
            (void) compiler;
            bt_cmd_extend(cmd, source_files);
        }

        void bt__gnu_compiler_specify_output_name(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const char* output_name) {
            (void) compiler;
            bt_cmd_add_many(cmd, "-o", output_name);
        }

        void bt__gnu_compiler_no_linking(struct Bt_Compiler* compiler, Bt_Cmd* cmd) {
            (void) compiler;
            bt_cmd_append(cmd, "-c");
        }

        void bt__gnu_compiler_add_precompiled_header(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const char* filename) {
            (void) compiler;
            bt_cmd_add_many(cmd, "-include", filename);
        }

        void bt__gnu_compiler_add_precompiled_headers(struct Bt_Compiler* compiler, Bt_Cmd* cmd, const Bt_String_Array* filenames) {
            (void) compiler;
            size_t i;
            const char* filename;
            bt_da_foreach(i, filename, filenames) {
                bt_cmd_add_many(cmd, "-include", filename);
            }
        }

        void bt__gnu_compiler_turn_on_optimizations(struct Bt_Compiler* compiler, Bt_Cmd* cmd) {
            (void) compiler;
            bt_cmd_append(cmd, "-O3");
        }

        void bt__gnu_compiler_enable_all_warnings(struct Bt_Compiler* compiler, Bt_Cmd* cmd) {
            (void) compiler;
            bt_cmd_add_many(cmd, "-Wall", "-Wextra");
        }

        void bt__gnu_compiler_treat_warnings_as_errors(struct Bt_Compiler* compiler, Bt_Cmd* cmd) {
            (void) compiler;
            bt_cmd_append(cmd, "-Werror");
        }

        void bt__gnu_compiler_generate_debug_symbols(struct Bt_Compiler* compiler, Bt_Cmd* cmd) {
            (void) compiler;
            bt_cmd_append(cmd, "-g3");
        }

        char* bt__gnu_compiler_source_file_to_object_filename(struct Bt_Compiler* compiler, const char* build_directory, const char* filename) {
            (void) compiler;

            return bt_concat_paths(build_directory, bt_arena_sprintf("%s.o", filename));
        }

        char* bt__gnu_compiler_source_file_to_precompiled_header_filename(struct Bt_Compiler* compiler, const char* filename) {
            (void) compiler;

            return bt_arena_sprintf("%s.gch", filename);
        }

        Bt_Compiler* bt_create_gnu_compiler(char* c_standard, char* cxx_standard) {
            Bt_Compiler* compiler = bt_arena_malloc(sizeof(*compiler));
            memset(compiler, 0, sizeof(*compiler));

            compiler->name = "gnu";

        #ifdef BT_WINDOWS
            compiler->executable_extension = ".exe";
        #else // BT_WINDOWS
            compiler->executable_extension = ".out";
        #endif // BT_WINDOWS

            bt_cmd_append(&compiler->base_c_compile_command, "gcc");
            bt_cmd_append(&compiler->base_cxx_compile_command, "g++");
            bt_cmd_append(&compiler->base_linker_command, "g++");

            if (c_standard) {
                bt_cmd_append(&compiler->base_c_compile_command, bt_arena_sprintf("-std=%s", c_standard));
            }
            if (cxx_standard) {
                bt_cmd_append(&compiler->base_cxx_compile_command, bt_arena_sprintf("-std=%s", cxx_standard));
            }

            compiler->generate_static_library = bt__gnu_compiler_generate_static_library;
            compiler->get_static_library_name = bt__gnu_compiler_get_static_library_name;
            compiler->change_c_compiler_name = bt__gnu_compiler_change_c_compiler_name;
            compiler->change_cxx_compiler_name = bt__gnu_compiler_change_cxx_compiler_name;
            compiler->change_linker_command_name = bt__gnu_compiler_change_linker_command_name;
            compiler->add_include_directory = bt__gnu_compiler_add_include_directory;
            compiler->add_include_directories = bt__gnu_compiler_add_include_directories;
            compiler->add_library_directory = bt__gnu_compiler_add_library_directory;
            compiler->add_library_directories = bt__gnu_compiler_add_library_directories;
            compiler->add_library = bt__gnu_compiler_add_library;
            compiler->add_libraries = bt__gnu_compiler_add_libraries;
            compiler->add_define = bt__gnu_compiler_add_define;
            compiler->add_source_file = bt__gnu_compiler_add_source_file;
            compiler->add_source_files = bt__gnu_compiler_add_source_files;
            compiler->add_file_to_linker = bt__gnu_add_file_to_linker;
            compiler->add_files_to_linker = bt__gnu_add_files_to_linker;
            compiler->specify_output_name = bt__gnu_compiler_specify_output_name;
            compiler->no_linking = bt__gnu_compiler_no_linking;
            compiler->add_precompiled_header = bt__gnu_compiler_add_precompiled_header;
            compiler->add_precompiled_headers = bt__gnu_compiler_add_precompiled_headers;
            compiler->turn_on_optimizations = bt__gnu_compiler_turn_on_optimizations;
            compiler->enable_all_warnings = bt__gnu_compiler_enable_all_warnings;
            compiler->treat_warnings_as_errors = bt__gnu_compiler_treat_warnings_as_errors;
            compiler->generate_debug_symbols = bt__gnu_compiler_generate_debug_symbols;
            compiler->source_file_to_object_filename = bt__gnu_compiler_source_file_to_object_filename;
            compiler->source_file_to_precompiled_header_filename = bt__gnu_compiler_source_file_to_precompiled_header_filename;

            Bt__gnu_compiler_extra_data* extra_data = bt_arena_malloc(sizeof(*extra_data));
            memset(extra_data, 0, sizeof(*extra_data));
            bt_cmd_append(&extra_data->base_archive_command, "ar");
            bt_cmd_append(&extra_data->base_archive_command, "rcs");
            bt_cmd_append(&extra_data->base_archive_command, "-o");

            compiler->extra_data = extra_data;

            return compiler;
        }

        void bt_destroy_gnu_compiler(Bt_Compiler* gnu_compiler) {
            bt_cmd_free(&gnu_compiler->base_c_compile_command);
            bt_cmd_free(&gnu_compiler->base_cxx_compile_command);
            bt_cmd_free(&gnu_compiler->base_linker_command);

            Bt__gnu_compiler_extra_data* extra_data = (Bt__gnu_compiler_extra_data*)gnu_compiler->extra_data;
            bt_cmd_free(&extra_data->base_archive_command);
            bt_arena_free(extra_data);

            bt_arena_free(gnu_compiler);
        }
    // END_SECTION: Gnu
    
    // BEGIN_SECTION: Compiler Shortcut
        Bt_Compiler* bt__lcompiler;
        void bt_compiler_set(Bt_Compiler* compiler) {
            bt__lcompiler = compiler;
        }

        Bt_Compiler* bt_compiler_get(void) {
            return bt__lcompiler;
        }

        Bt_String_Array* bt_compiler_get_base_c_compile_command(void) {
            return &bt__lcompiler->base_c_compile_command;
        }

        Bt_String_Array* bt_compiler_get_base_cxx_compile_command(void) {
            return &bt__lcompiler->base_cxx_compile_command;
        }

        Bt_String_Array* bt_compiler_get_base_linker_command(void) {
            return &bt__lcompiler->base_linker_command;
        }

        const char* bt_compiler_get_executable_extension(void) {
            return bt__lcompiler->executable_extension;
        }

        void bt_compiler_generate_static_library(Bt_Cmd* cmd, Bt_String_Array* files, const char* output_location, const char* name) {
            bt__lcompiler->generate_static_library(bt__lcompiler, cmd, files, output_location, name);
        }

        const char* bt_compiler_get_static_library_name(const char* name, const char* output_location) {
            return bt__lcompiler->get_static_library_name(bt__lcompiler, name, output_location);
        }

        void bt_compiler_change_c_compiler_name(char* c_compiler) {
            bt__lcompiler->change_c_compiler_name(bt__lcompiler, c_compiler);
        }

        void bt_compiler_change_cxx_compiler_name(char* cpp_compiler) {
            bt__lcompiler->change_cxx_compiler_name(bt__lcompiler, cpp_compiler);
        }

        void bt_compiler_change_linker_command_name(char* linker) {
            bt__lcompiler->change_linker_command_name(bt__lcompiler, linker);
        }

        void bt_compiler_add_include_directory(Bt_Cmd* cmd, char* directory) {
            bt__lcompiler->add_include_directory(bt__lcompiler, cmd, directory);
        }

        void bt_compiler_add_include_directories(Bt_Cmd* cmd, const Bt_String_Array* directories) {
            bt__lcompiler->add_include_directories(bt__lcompiler, cmd, directories);
        }

        void bt_compiler_add_library_directory(Bt_Cmd* cmd, const char* directory) {
            bt__lcompiler->add_library_directory(bt__lcompiler, cmd, directory);
        }

        void bt_compiler_add_library_directories(Bt_Cmd* cmd, const Bt_String_Array* directories) {
            bt__lcompiler->add_library_directories(bt__lcompiler, cmd, directories);
        }

        void bt_compiler_add_library(Bt_Cmd* cmd, const char* library_name) {
            bt__lcompiler->add_library(bt__lcompiler, cmd, library_name);
        }

        void bt_compiler_add_libraries(Bt_Cmd* cmd, const Bt_String_Array* library_names) {
            bt__lcompiler->add_libraries(bt__lcompiler, cmd, library_names);
        }

        void bt_compiler_add_define(Bt_Cmd* cmd, const char* define_name, const char* define_value) {
            bt__lcompiler->add_define(bt__lcompiler, cmd, define_name, define_value);
        }

        void bt_compiler_add_source_file(Bt_Cmd* cmd, const char* source_file) {
            bt__lcompiler->add_source_file(bt__lcompiler, cmd, source_file);
        }

        void bt_compiler_add_source_files(Bt_Cmd* cmd, const Bt_String_Array* source_files) {
            bt__lcompiler->add_source_files(bt__lcompiler, cmd, source_files);
        }

        void bt_compiler_add_file_to_linker(Bt_Cmd* cmd, const char* source_file) {
            bt__lcompiler->add_file_to_linker(bt__lcompiler, cmd, source_file);
        }

        void bt_compiler_add_files_to_linker(Bt_Cmd* cmd, const Bt_String_Array* source_files) {
            bt__lcompiler->add_files_to_linker(bt__lcompiler, cmd, source_files);
        }

        void bt_compiler_specify_output_name(Bt_Cmd* cmd, char* output_name) {
            bt__lcompiler->specify_output_name(bt__lcompiler, cmd, output_name);
        }

        void bt_compiler_no_linking(Bt_Cmd* cmd) {
            bt__lcompiler->no_linking(bt__lcompiler, cmd);
        }

        void bt_compiler_add_precompiled_header(Bt_Cmd* cmd, const char* filename) {
            bt__lcompiler->add_precompiled_header(bt__lcompiler, cmd, filename);
        }

        void bt_compiler_add_precompiled_headers(Bt_Cmd* cmd, const Bt_String_Array* filenames) {
            bt__lcompiler->add_precompiled_headers(bt__lcompiler, cmd, filenames);
        }

        char* bt_compiler_source_file_to_object_filename(const char* build_directory, const char* filename) {
            return bt__lcompiler->source_file_to_object_filename(bt__lcompiler, build_directory, filename);
        }

        char* bt_compiler_source_file_to_precompiled_header_filename(const char* filename) {
            return bt__lcompiler->source_file_to_precompiled_header_filename(bt__lcompiler, filename);
        }

        void bt_compiler_turn_on_optimizations(Bt_Cmd* cmd) {
            if (bt__lcompiler->turn_on_optimizations == NULL) {
                return;
            }
            bt__lcompiler->turn_on_optimizations(bt__lcompiler, cmd);
        }

        void bt_compiler_enable_all_warnings(Bt_Cmd* cmd) {
            if (bt__lcompiler->enable_all_warnings == NULL) {
                return;
            }
            bt__lcompiler->enable_all_warnings(bt__lcompiler, cmd);
        }

        void bt_compiler_treat_warnings_as_errors(Bt_Cmd* cmd) {
            if (bt__lcompiler->treat_warnings_as_errors == NULL) {
                return;
            }
            bt__lcompiler->treat_warnings_as_errors(bt__lcompiler, cmd);
        }

        void bt_compiler_generate_debug_symbols(Bt_Cmd* cmd) {
            if (bt__lcompiler->generate_debug_symbols == NULL) {
                return;
            }
            bt__lcompiler->generate_debug_symbols(bt__lcompiler, cmd);
        }
    // END_SECTION: Compiler Shortcut

    const char* bt__ibuild_dir;
    const char* bt_get_build_directory(void) {
        return bt__ibuild_dir;
    }

    void bt_set_build_directory(const char* build_directory) {
        bt__ibuild_dir = build_directory;
    }
// END_SECTION: Compiler

// BEGIN_SECTION: Fs
    char* bt__concat__paths(const char* first, ...) {
        if (!first) return "";

        const char* part;
        Bt_String_Array args = {0};

        va_list va;
        va_start(va, first);

        for (part = first; part != NULL ; part = va_arg(va,char*)) {
            bt_da_append(&args, part);
        }
        va_end(va);

        Bt_String_Builder sb = {0};
        size_t i;
        const char** part_ref;
        bt_da_foreach_ref(i, part_ref, &args) {
            Bt_String_View part_sv = bt_sv_from_cstr(*part_ref);

            if (bt_sv_eq(part_sv, bt_sv_from_cstr(".")) && i != 0) continue;
            if (bt_sv_eq(part_sv, bt_sv_from_cstr(".."))) {
                bt_sb_append_cstr(&sb, "../");
                continue;
            }

            if (bt_sv_startswith(part_sv, "./") || bt_sv_startswith(part_sv, ".\\")) {
                part_sv.size -= 2;
                part_sv.data += 2;
                bt_sb_append_buf(&sb, part_sv.data, part_sv.size);
            } else {
                bt_sb_append_buf(&sb, part_sv.data, part_sv.size);
            }
            if (sb.size == 0) {
                bt_sb_append_cstr(&sb, "./");
            } else if (sb.items[sb.size - 1] != '/' && sb.items[sb.size - 1] != '\\') {
            #ifdef BT_WINDOWS
                bt_sb_append_char(&sb, '\\');
            #else
                bt_sb_append_char(&sb, '/');
            #endif
            }
        }
        // chop the last '/'
        sb.size--;
        bt_sb_append_null(&sb);

        char* cstr = bt_arena_strdup(bt_sb_as_cstr(&sb));
        bt_sb_free(&sb);
        bt_da_free(&args);

        return cstr;
    }

    bool bt_path_exists(const char* path) {
        #ifdef BT_WINDOWS
            return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
        #else // BT_WINDOWS
            return access(path, F_OK) == 0;
        #endif // BT_WINDOWS
    }

    bool bt_read_entire_file(const char *path, Bt_String_Builder *sb) {
        bool result = true;

        FILE *f = fopen(path, "rb");
        if (f == NULL)                 BT_DEFER(false);
        if (fseek(f, 0, SEEK_END) < 0) BT_DEFER(false);
        long m = ftell(f);
        if (m < 0)                     BT_DEFER(false);
        if (fseek(f, 0, SEEK_SET) < 0) BT_DEFER(false);

        size_t new_size = sb->size + m;
        if (new_size > sb->capacity) {
            sb->items = bt_arena_realloc(sb->items, sb->capacity*sizeof(*sb->items), new_size);
        }

        fread(sb->items + sb->size, m, 1, f);
        if (ferror(f)) {
            // TODO: Afaik, ferror does not set errno. So the error reporting in defer is not correct in this case.
            BT_DEFER(false);
        }
        sb->size = new_size;

        defer:
            if (!result) bt_log(BT_ERROR, "Could not read file %s: %s", path, strerror(errno));
            if (f) fclose(f);
            return result;
    }

    bool bt_write_entire_file(const char* path, const void* data, size_t size) {
        #ifdef BT_WINDOWS
            HANDLE hFile = CreateFileA(
                    path,                       // File path
                    GENERIC_WRITE,              // Open for writing
                    0,                          // No sharing
                    NULL,                       // Default security
                    CREATE_ALWAYS,              // Create or truncate the file
                    FILE_ATTRIBUTE_NORMAL,     // Normal file
                    NULL                        // No template file
                );

            if (hFile == INVALID_HANDLE_VALUE) {
                // Failed to open/create the file
                return false;
            }

            // Write the data to the file
            DWORD bytesWritten;
            BOOL result = WriteFile(
                hFile,                      // File handle
                data,                       // Data to write
                (DWORD)size,                // Size of data
                &bytesWritten,              // Number of bytes written
                NULL                        // No overlapped structure
            );

            // Close the file handle
            CloseHandle(hFile);

            // Check if the write operation was successful
            if (!result || bytesWritten != size) {
                return false;
            }

            return true;
        #else // BT_WINDOWS
            int fd = open(path, O_TRUNC | O_WRONLY | O_CREAT, 0666);

            if (fd <= 0) {
                return false;
            }

            if (write(fd, data, size) == -1) {
                return false;
            }

            close(fd);

            return true;
        #endif // BT_WINDOWS
    }

    uint64_t bt_get_get_last_modification_date(const char* path) {
        #ifdef BT_WINDOWS
            WIN32_FILE_ATTRIBUTE_DATA fileInfo;
            if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fileInfo)) {
                // Handle error: failed to get file attributes
                bt_log(BT_ERROR, "Could not get file attributes of %s: %lu\n", path, bt_win32_error_message(GetLastError()));
                return 0;
            }

            // Extract the last modification time from the file info
            FILETIME lastWriteTime = fileInfo.ftLastWriteTime;

            // Convert FILETIME to a 64-bit integer representing the number of 100-nanosecond intervals since January 1, 1601 (UTC)
            ULARGE_INTEGER uli;
            uli.LowPart = lastWriteTime.dwLowDateTime;
            uli.HighPart = lastWriteTime.dwHighDateTime;

            // Convert Windows FILETIME to Unix time
            // 1. Calculate the difference between the Windows epoch (1601) and the Unix epoch (1970) in 100-nanosecond intervals
            const uint64_t WINDOWS_TICK = 10000000; // 100-nanosecond intervals in a second
            const uint64_t SEC_TO_UNIX_EPOCH = 11644473600LL; // Seconds from 1601 to 1970

            // 2. Subtract the difference and convert to seconds
            uint64_t unixTime = (uli.QuadPart / WINDOWS_TICK) - SEC_TO_UNIX_EPOCH;

            return unixTime;
        #else // BT_WINDOWS
            struct stat attr;
            if (stat(path, &attr) < 0) {
                bt_log(BT_ERROR, "Could not get stat of file %s: %s", path, strerror(errno));
            }
            return attr.st_mtime;
        #endif // BT_WINDOWS
    }

    const char* bt_parent(const char* path) {
        size_t size = strlen(path);

        while (size > 0 && (path[size - 1] != '\\' && path[size - 1] != '/')) size--;

        if (size == 0) return "";

        char* ret = bt_arena_malloc(size + 1);
        memcpy(ret, path, size);
        ret[size] = '\0';

        return ret;
    }

    bool bt_path_is_file(const char* path) {
        if (!bt_path_exists(path)) {
            return false;
        }
        #ifdef BT_WINDOWS
            attr = GetFileAttributesA(path);
            if (attr == INVALID_FILE_ATTRIBUTES) {
                fprintf(stderr, "GetFileAttributesA failed for `%s`: %zu", path, bt_win32_error_message(GetLastError()));
                return 0;
            }
            return (attr & FILE_ATTRIBUTE_DIRECTORY) == 0;
        #else /* BT_WINDOWS */
            struct stat statbuf;
            if (stat(path, &statbuf) < 0) {
                fprintf(stderr, "stat failed for `%s`: %s", path, strerror(errno));
                return 0;
            }

            return (statbuf.st_mode & S_IFMT) == S_IFREG;
        #endif /* BT_WINDOWS */
    }

    bool bt_path_is_directory(const char* path) {
        if (!bt_path_exists(path)) {
                return false;
            }
            #ifdef BT_WINDOWS
                attr = GetFileAttributesA(path);
                if (attr == INVALID_FILE_ATTRIBUTES) {
                    fprintf(stderr, "GetFileAttributesA failed for `%s`: %zu", path, bt_win32_error_message(GetLastError()));
                    return 0;
                }
                return (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
            #else /* BT_WINDOWS */
                struct stat statbuf;
                if (stat(path, &statbuf) < 0) {
                    fprintf(stderr, "stat failed for `%s`: %s", path, strerror(errno));
                    return 0;
                }

                return (statbuf.st_mode & S_IFMT) == S_IFDIR;
            #endif /* BT_WINDOWS */
    }

    bool bt_mkdir_parent_if_not_exists(const char* path) {
        size_t checkpoint = bt_arena_get_checkpoint();

        size_t path_size = strlen(path);
        char* temp_str = bt_arena_strdup(path);

        for (size_t k = path_size; k > 0; k--) {
            k--;

            if (temp_str[k] == '/' || temp_str[k] == '\\') {
                temp_str[k] = '\0';
                if (bt_path_exists(temp_str)) {
                    bt_arena_rewind(checkpoint);
                    return true;
                }

                return bt_mkdir_recursivly_if_not_exists(temp_str);
                break;
            }

            k++;
        }
        bt_log(BT_ERROR, "path `%s` doesnt have a parent", path);
        bt_arena_rewind(checkpoint);
        return false;
    }

    bool bt_mkdir_if_not_exists(const char* path) {
        #ifdef _WIN32
            // Use Windows API to create the directory
            if (CreateDirectoryA(path, NULL) == 0) {
                DWORD error = GetLastError();
                if (error == ERROR_ALREADY_EXISTS) {
                    return true; // Directory already exists
                }
                fprintf(stderr, "GetFileAttributesA failed for `%s`: %zu", path, bt_win32_error_message(GetLastError()));
                return false;
            }
        #else
            // Use POSIX mkdir to create the directory
            if (mkdir(path, 0755) != 0) {
                if (errno == EEXIST) {
                    return true; // Directory already exists
                }
                fprintf(stderr, "stat failed for `%s`: %s", path, strerror(errno));
                return false;
            }
        #endif

            return true; // Directory created successfully
    }

    bool bt_mkdir_recursivly_if_not_exists(const char* path) {
        size_t savepoint = bt_arena_get_checkpoint();
        char* file_path = bt_arena_strdup(path);
        Bt_Log_Level previous_log_level = bt_get_min_log_level();
        bt_set_min_log_level(BT_NOLOG);
        char* p;
        for (p = strchr(file_path + 1, '/'); p; p = strchr(p + 1, '/')) {
            *p = '\0';
            if (!bt_mkdir_if_not_exists(file_path)) {
                    bt_arena_rewind(savepoint);
                    bt_set_min_log_level(previous_log_level);
                    bt_log(BT_ERROR, "could not create directory `%s`: %s", path, strerror(errno));
                    return false;
            }
            *p = '/';
        }
        bt_mkdir_if_not_exists(path);
        bt_arena_rewind(savepoint);
        bt_set_min_log_level(previous_log_level);
        return true;
    }
// END_SECTION: Fs

// BEGIN_SECTION: Special Files
    typedef struct Bt_Log_File_Entry {
        uint64_t time;
        const char* name;
    } Bt_Log_File_Entry;

    typedef struct Bt_Log_File {
        Bt_Log_File_Entry* items;
        uint32_t size;
        uint32_t capacity;
    } Bt_Log_File;

    typedef struct Bt_Include_Structure_Entry {
        const char* filename;
        Bt_String_Array includes;
    } Bt_Include_Structure_Entry;

    typedef struct Bt_Include_Structure_File {
        Bt_Include_Structure_Entry* items;
        uint32_t size;
        uint32_t capacity;
    } Bt_Include_Structure_File;

    typedef struct Bt_Compile_Commands_Entry {
        const char* filename;
        const char* command;
    } Bt_Compile_Commands_Entry;

    typedef struct Bt_Compile_Commands_Structure {
        Bt_Compile_Commands_Entry* items;
        size_t size;
        size_t capacity;
    } Bt_Compile_Commands_Structure;

    bool bt_special_files_init(const char* build_directory);
    bool bt_special_files_close(const char* build_directory);

    // void bt_log_file_update_entry(const char* name);
    // uint64_t bt_log_file_get_time(const char* name);
    // bool bt_was_file_modified(const char* filename);

    void bt_include_structure_update_entry(const char* filename, Bt_String_Array* includes);
    bool bt_include_structure_contains(const char* filename);
    Bt_String_Array bt_include_structure_get(const char* filename);

    void bt_log_file_add_entry(Bt_Log_File* lf, const char* name, uint64_t time);
    void bt_log_file_to_buffer(Bt_Log_File* lf, Bt_String_Builder* sb);
    Bt_Log_File bt_log_file_from_buffer(const uint8_t* buffer, size_t buffer_size);

    void bt_include_structure_file_to_buffer(Bt_Include_Structure_File* isf, Bt_String_Builder* sb);
    Bt_Include_Structure_File bt_include_structure_File_from_buffer(const uint8_t* buffer, size_t buffer_size);

    void bt_compile_commands_to_buffer(Bt_Compile_Commands_Structure* ccs, Bt_String_Builder* sb);
    Bt_Compile_Commands_Structure bt_compile_commands_structure_from_buffer(const uint8_t* buffer, size_t buffer_size);

    void bt_compile_commands_update_entry(const char* name, Bt_Cmd cmd);
    bool bt_compile_commands_contains(const char* name);
    int bt_compile_commands_is_eq(const char* name, Bt_Cmd cmd);

    static Bt_Log_File bt__special_files__log_file = {0};
    static Bt_Include_Structure_File bt__special_files__include_structure = {0};
    static Bt_Compile_Commands_Structure bt__special_files__compile_commands = {0};

    bool bt_special_files_init(const char* build_directory) {
        if (bt_path_exists(bt_concat_paths(build_directory, "log.mtimes"))) {
            Bt_String_Builder sb = {0};

            if (!bt_read_entire_file(bt_concat_paths(build_directory, "log.mtimes"), &sb)) return false;

            if (sb.size != 0) {
                bt__special_files__log_file = bt_log_file_from_buffer((uint8_t*)sb.items, sb.size);
            bt_sb_free(&sb);
            } else {
                memset(&bt__special_files__log_file, 0, sizeof(bt__special_files__log_file));
            }
        }

        if (bt_path_exists(bt_concat_paths(build_directory, "include.structure"))) {
            Bt_String_Builder sb = {0};

            if (!bt_read_entire_file(bt_concat_paths(build_directory, "include.structure"), &sb)) return false;

            if (sb.size != 0) {
                bt__special_files__include_structure = bt_include_structure_File_from_buffer((uint8_t*)sb.items, sb.size);
                bt_sb_free(&sb);
            } else {
                memset(&bt__special_files__include_structure, 0, sizeof(bt__special_files__include_structure));
            }
        }


        if (bt_path_exists(bt_concat_paths(build_directory, "compile.commands"))) {
            Bt_String_Builder sb = {0};

            if (!bt_read_entire_file(bt_concat_paths(build_directory, "compile.commands"), &sb)) return false;

            if (sb.size != 0) {
                bt__special_files__compile_commands = bt_compile_commands_structure_from_buffer((uint8_t*)sb.items, sb.size);
                bt_sb_free(&sb);
            } else {
                memset(&bt__special_files__compile_commands, 0, sizeof(bt__special_files__compile_commands));
            }
        }

        return true;
    }

    bool bt_special_files_close(const char* build_directory) {
        Bt_String_Builder sb = {0};
        bt_log_file_to_buffer(&bt__special_files__log_file, &sb);
        if (!bt_write_entire_file(bt_concat_paths(build_directory, "log.mtimes"), sb.items, sb.size)) return false;
        bt_da_free(&bt__special_files__log_file);
        bt_da_free(&sb);

        bt_include_structure_file_to_buffer(&bt__special_files__include_structure, &sb);
        if (!bt_write_entire_file(bt_concat_paths(build_directory, "include.structure"), sb.items, sb.size)) return false;
        bt_da_free(&bt__special_files__include_structure);
        bt_da_free(&sb);

        bt_compile_commands_to_buffer(&bt__special_files__compile_commands, &sb);
        if (!bt_write_entire_file(bt_concat_paths(build_directory, "compile.commands"), sb.items, sb.size)) return false;
        bt_da_free(&bt__special_files__compile_commands);
        bt_da_free(&sb);

        return true;
    }

    void bt_log_file_add_entry(Bt_Log_File* lf, const char* name, uint64_t time) {
        Bt_Log_File_Entry entry;
        Bt_Log_File_Entry* entry_ref;
        size_t i;

        bt_da_foreach_ref(i, entry_ref, lf) {
            if (strcmp(name, entry_ref->name) == 0) {
                entry_ref->time = time;
                return;
            }
        }

        entry.name = name;
        entry.time = time;
        bt_da_append(lf, entry);
    }

    void bt_log_file_update_entry(const char* name) {
        bt_log_file_add_entry(&bt__special_files__log_file, name, bt_get_get_last_modification_date(name));
    }

    uint64_t bt_log_file_get_time(const char* name) {
        size_t i;
        Bt_Log_File_Entry entry;
        bt_da_foreach(i, entry, &bt__special_files__log_file) {
            if (strcmp(entry.name, name) == 0) {
                return entry.time;
            }
        }

        return 0;
    }

    void bt_log_file_to_buffer(Bt_Log_File* lf, Bt_String_Builder* sb) {
        Bt_Buffer_Writer bw = {0};
        bt_buffer_writer_init(&bw, 10 * 1024);
        for (size_t i = 0; i < lf->size; i++) {
            bt_buffer_writer_insert_string(&bw, lf->items[i].name);
            bt_buffer_writer_insert_u64(&bw, lf->items[i].time);
            bt_buffer_writer_insert_i8(&bw, '\n');
        }
        bt_sb_append_buf(sb, bw.buffer, bw.size);

        bt_buffer_writer_free(&bw);
    }

    Bt_Log_File bt_log_file_from_buffer(const uint8_t* buffer, size_t buffer_size) {
        Bt_Buffer_Reader br = {0};
        br.buffer = buffer;
        br.buffer_size = buffer_size;

        Bt_Log_File ret = {0};
        Bt_Log_File_Entry entry = {0};

        while (!bt_buffer_reader_is_empty(&br)) {
            entry.name = bt_buffer_reader_extract_string(&br, NULL);
            entry.time = bt_buffer_reader_extract_u64(&br);
            BT_ASSERT(bt_buffer_reader_extract_i8(&br) == '\n');

            bt_da_append(&ret, entry);
        }

        return ret;
    }

    bool bt_was_file_modified(const char* filename) {
        uint64_t mtime = bt_log_file_get_time(filename);
        if (mtime == 0) {
            return true;
        }
        uint64_t last_mtime = bt_get_get_last_modification_date(filename);

        return mtime != last_mtime;
    }

    void bt_include_structure_file_to_buffer(Bt_Include_Structure_File* isf, Bt_String_Builder* sb) {
        Bt_Buffer_Writer bw = {0};
        bt_buffer_writer_init(&bw, 10 * 1024);
        bt_buffer_writer_insert_u32(&bw, isf->size);
        for (uint32_t i = 0; i < isf->size; i++) {
            bt_buffer_writer_insert_string(&bw, isf->items[i].filename);
            bt_buffer_writer_insert_u32(&bw, isf->items[i].includes.size);
            for (uint32_t j = 0; j < isf->items[i].includes.size; j++) {
                bt_buffer_writer_insert_string(&bw, isf->items[i].includes.items[j]);
            }
        }

        bt_sb_append_buf(sb, bw.buffer, bw.size);
        bt_buffer_writer_free(&bw);
    }

    Bt_Include_Structure_File bt_include_structure_File_from_buffer(const uint8_t* buffer, size_t buffer_size) {
        Bt_Buffer_Reader br = {0};
        br.buffer = buffer;
        br.buffer_size = buffer_size;

        Bt_Include_Structure_File isf = {0};

        uint32_t entry_count = bt_buffer_reader_extract_u32(&br);
        for (uint32_t i = 0; i < entry_count; i++) {
            Bt_Include_Structure_Entry entry = {0};
            entry.filename = bt_arena_strdup(bt_buffer_reader_extract_string(&br, NULL));
            uint32_t include_count = bt_buffer_reader_extract_u32(&br);
            for (uint32_t j = 0; j < include_count; j++) {
                bt_da_append(&entry.includes, bt_arena_strdup(bt_buffer_reader_extract_string(&br, NULL)));
            }
            bt_da_append(&isf, entry);
        }

        return isf;
    }

    void bt_include_structure_update_entry(const char* filename, Bt_String_Array* includes) {
        Bt_Include_Structure_Entry entry;
        Bt_Include_Structure_Entry* entry_ref;
        size_t i;

        bt_da_foreach_ref(i, entry_ref, &bt__special_files__include_structure) {
            if (strcmp(filename, entry_ref->filename) == 0) {
                entry_ref->includes = *includes;
                return;
            }
        }

        entry.filename = bt_arena_strdup(filename);
        entry.includes = *includes;
        bt_da_append(&bt__special_files__include_structure, entry);
    }

    bool bt_include_structure_contains(const char* filename) {
        Bt_Include_Structure_Entry* entry_ref;
        size_t i;

        bt_da_foreach_ref(i, entry_ref, &bt__special_files__include_structure) {
            if (strcmp(filename, entry_ref->filename) == 0) {
                return true;
            }
        }
        return false;
    }

    Bt_String_Array bt_include_structure_get(const char* filename) {
        Bt_Include_Structure_Entry* entry_ref;
        size_t i;

        bt_da_foreach_ref(i, entry_ref, &bt__special_files__include_structure) {
            if (strcmp(filename, entry_ref->filename) == 0) {
                return entry_ref->includes;
            }
        }
        BT_UNREACHABLE("bt_include_structure_get");
    }

    void bt_compile_commands_to_buffer(Bt_Compile_Commands_Structure* ccs, Bt_String_Builder* sb) {
        Bt_Buffer_Writer bw = {0};
        bt_buffer_writer_init(&bw, 10 * 1024);
        bt_buffer_writer_insert_u32(&bw, ccs->size);
        for (uint32_t i = 0; i < ccs->size; i++) {
            bt_buffer_writer_insert_string(&bw, ccs->items[i].filename);
            bt_buffer_writer_insert_string(&bw, ccs->items[i].command);
        }

        bt_sb_append_buf(sb, bw.buffer, bw.size);
        bt_buffer_writer_free(&bw);
    }

    Bt_Compile_Commands_Structure bt_compile_commands_structure_from_buffer(const uint8_t* buffer, size_t buffer_size) {
        Bt_Buffer_Reader br = {0};
        br.buffer = buffer;
        br.buffer_size = buffer_size;

            Bt_Compile_Commands_Structure css = {0};

            uint32_t entry_count = bt_buffer_reader_extract_u32(&br);
            for (uint32_t i = 0; i < entry_count; i++) {
                Bt_Compile_Commands_Entry entry = {0};
                entry.filename = bt_arena_strdup(bt_buffer_reader_extract_string(&br, NULL));
                entry.command = bt_arena_strdup(bt_buffer_reader_extract_string(&br, NULL));

                bt_da_append(&css, entry);
            }

            return css;
    }

    void bt_compile_commands_update_entry(const char* name, Bt_Cmd cmd) {
        Bt_String_Builder result = {0};
        for (size_t i = 0; i < cmd.size; i++) {
            char* escaped =  bt_escape_argument(cmd.items[i]);
            bt_sb_append_char(&result, '|');
            bt_sb_append_char(&result, '|');
            bt_sb_append_cstr(&result, escaped);
            bt_sb_append_char(&result, '|');
            bt_sb_append_char(&result, '|');
        }
        bt_sb_append_null(&result);

        for (size_t i = 0; i < bt__special_files__compile_commands.size; i++) {
            if (strcmp(bt__special_files__compile_commands.items[i].filename, name) == 0) {
                bt__special_files__compile_commands.items[i].command = bt_sb_as_cstr(&result);
                return;
            }
        }
        
        Bt_Compile_Commands_Entry entry;
        entry.filename = name;
        entry.command = bt_sb_as_cstr(&result);
        bt_da_append(&bt__special_files__compile_commands, entry);
    }

    bool bt_compile_commands_contains(const char* name) {
        for (size_t i = 0; i < bt__special_files__compile_commands.size; i++) {
            if (strcmp(bt__special_files__compile_commands.items[i].filename, name) == 0) {
                return true;
            }
        }
        return false;
    }
    
    int bt_compile_commands_is_eq(const char* name, Bt_Cmd cmd) {
        Bt_String_Builder result = {0};
        for (size_t i = 0; i < cmd.size; i++) {
            char* escaped =  bt_escape_argument(cmd.items[i]);
            bt_sb_append_char(&result, '|');
            bt_sb_append_char(&result, '|');
            bt_sb_append_cstr(&result, escaped);
            bt_sb_append_char(&result, '|');
            bt_sb_append_char(&result, '|');
        }
        bt_sb_append_null(&result);
        
        for (size_t i = 0; i < bt__special_files__compile_commands.size; i++) {
            if (strcmp(bt__special_files__compile_commands.items[i].filename, name) == 0) {
                return strcmp(bt_sb_as_cstr(&result), bt__special_files__compile_commands.items[i].command) == 0;
            }
        }
        return 0;
    }
// END_SECTION: Special Files


// BEGIN_SECTION: BuildSys
    // BEGIN_SECTION: SLib, Exe, BSpec utils
        void bt_slib_set_name(Bt_Static_Library* slib, const char* name) {
            slib->name = name;
        }

        void bt_slib_set_output_location(Bt_Static_Library* slib, const char* output_location) {
            slib->output_location = output_location;
        }

        void bt_slib_add_source(Bt_Static_Library* slib, const char* source) {
            bt_da_append(&slib->sources, source);
        }

        void bt_slib_add_include_directory(Bt_Static_Library* slib, const char* include_directory) {
            bt_da_append(&slib->include_directories, include_directory);
        }

        void bt_slib_add_precompiled_header(Bt_Static_Library* slib, const char* precompiled_header) {
            bt_da_append(&slib->precompiled_headers, precompiled_header);
        }
        
        void bt_slib_add_extra_build_flag(Bt_Static_Library* slib, const char* extra_build_flag) {
            bt_da_append(&slib->extra_build_flags, extra_build_flag);
        }
        
        void bt_slib_add_define(Bt_Static_Library* slib, const char* define_name, const char* define_value) {
            Bt_Define define;
            define.name = define_name;
            define.value = define_value;
            bt_da_append(&slib->defines, define);
        }

        void bt_slib_add_library_directory(Bt_Static_Library* slib, const char* library_directory) {
            bt_da_append(&slib->library_directories, library_directory);
        }

        void bt_slib_add_library(Bt_Static_Library* slib, const char* library) {
            bt_da_append(&slib->libraries, library);
        }

        void bt_slib_add_dependency(Bt_Static_Library* slib, const char* dependency) {
            bt_da_append(&slib->dependencies, dependency);
        }

        void bt_exe_set_name(Bt_Executable* exe, const char* name) {
            exe->name = name;
        }

        void bt_exe_set_output_location(Bt_Executable* exe, const char* output_location) {
            exe->output_location = output_location;
        }

        void bt_exe_add_source(Bt_Executable* exe, const char* source) {
            bt_da_append(&exe->sources, source);
        }

        void bt_exe_add_precompiled_header(Bt_Executable* exe, const char* precompiled_header) {
            bt_da_append(&exe->precompiled_headers, precompiled_header);
        }

        void bt_exe_add_include_directory(Bt_Executable* exe, const char* include_directory) {
            bt_da_append(&exe->include_directories, include_directory);
        }

        void bt_exe_add_define(Bt_Executable* exe, const char* define_name, const char* define_value) {
            Bt_Define define;
            define.name = define_name;
            define.value = define_value;
            bt_da_append(&exe->defines, define);
        }

        void bt_exe_add_library(Bt_Executable* exe, const char* library) {
            bt_da_append(&exe->libraries, library);
        }

        void bt_exe_add_library_directory(Bt_Executable* exe, const char* library_directory) {
            bt_da_append(&exe->library_directories, library_directory);
        }

        void bt_exe_add_extra_build_flag(Bt_Executable* exe, const char* extra_build_flag) {
            bt_da_append(&exe->extra_build_flags, extra_build_flag);
        }

        void bt_exe_add_extra_link_flag(Bt_Executable* exe, const char* extra_link_flag) {
            bt_da_append(&exe->extra_link_flags, extra_link_flag);
        }

        void bt_exe_add_dependency(Bt_Executable* exe, const char* dependency) {
            bt_da_append(&exe->dependencies, dependency);
        }

        void bt_bspec_add_include_directory(Bt_Build_Spec* spec, const char* include_directory) {
            bt_da_append(&spec->include_directories, include_directory);
        }

        void bt_bspec_add_library_directory(Bt_Build_Spec* spec, const char* library_directory) {
            bt_da_append(&spec->library_directories, library_directory);
        }

        void bt_bspec_add_library(Bt_Build_Spec* spec, const char* library) {
            bt_da_append(&spec->libraries, library);
        }

        void bt_bspec_add_extra_define(Bt_Build_Spec* spec, const char* define_name, const char* define_value) {
            Bt_Define define;
            define.name = define_name;
            define.value = define_value;

            bt_da_append(&spec->extra_defines, define);
        }

        void bt_bspec_add_extra_build_flag(Bt_Build_Spec* spec, const char* extra_build_flag) {
            bt_da_append(&spec->extra_build_flags, extra_build_flag);
        }

        void bt_bspec_add_extra_link_flag(Bt_Build_Spec* spec, const char* extra_link_flag) {
            bt_da_append(&spec->extra_link_flags, extra_link_flag);
        }

        void bt_bspec_add_static_library(Bt_Build_Spec* spec, Bt_Static_Library* static_library) {
            bt_da_append(&spec->static_libraries, *static_library);
        }

        void bt_bspec_add_executable(Bt_Build_Spec* spec, Bt_Executable* executable) {
            bt_da_append(&spec->executables, *executable);
        }
    // END_SECTION: SLib, Exe, BSpec utils

    // BEGIN_SECTION: Helpers
        Bt_String_Array bt_get_includes_from_file(const char* filename, Bt_String_Array include_paths_to_search_in) {
            Bt_String_Builder sb = {0};
            bt_read_entire_file(filename, &sb);
            bt_sb_append_null(&sb);

            Bt_String_Array includes = {0};

            char* contents = sb.items;
            char* p2 = contents;
            while ((p2 = strchr(contents, '\n')) != NULL) {
                int64_t line_size = p2 - contents;
                while (line_size >= 0 && (contents[line_size] == '\n' || contents[line_size] == '\r')) {
                    --line_size;
                }
                if (line_size >= 0) {
                    bool is_not_blank = false;
                    for (char* p = contents; p < contents + line_size; p++) {
                        if (!isspace(*p)) {
                            is_not_blank = true;
                            break;
                        }
                    }
                    if (!is_not_blank) goto end_of_loop;

                    Bt_String_View sv = bt_sv_trim(bt_sv_from_parts(contents, line_size + 1));
                    if (!bt_sv_startswith(sv, "#")) goto end_of_loop;
                    // chop "#"
                    sv.size--;
                    sv.data++;
                    sv = bt_sv_trim(sv);
                    if (!sv.size) goto end_of_loop;

                    if (!bt_sv_startswith(sv, "include")) goto end_of_loop;
                    // chop "include"
                    sv.size -= 7;
                    sv.data += 7;
                    sv = bt_sv_trim(sv);
                    if (!sv.size) goto end_of_loop;

                    // 2 for the quotes and at least 1 for the filename
                    if (sv.size < 3) goto end_of_loop;
                    // chop qoutes/braces
                    sv.size -= 2;
                    sv.data += 1;

                    // include_paths_to_search
                    if (bt_sv_startswith(sv, "./")) {
                        // i have seen some truly shitty code that makes this necessary
                        while (bt_sv_startswith(sv, "./")) {
                            sv.size -= 2;
                            sv.data += 2;
                        }

                        char* path = bt_concat_paths(bt_parent(filename), bt_arena_cstr_from_sv(&sv));
                        size_t checkpoint = bt_arena_get_checkpoint();
                        if (bt_path_exists(path)) {
                            if (bt_path_is_file(path)) {
                                bt_da_append(&includes, path);
                            } else {
                                bt_arena_rewind(checkpoint);
                            }
                        } else {
                            bt_arena_rewind(checkpoint);
                        }
                        goto end_of_loop;
                    } else if (bt_sv_startswith(sv, "../")) {
                        // i have seen some truly shitty code that makes this necessary
                        while (bt_sv_startswith(sv, "../")) {
                            sv.size -= 3;
                            sv.data += 3;
                        }

                        char* path = bt_concat_paths(bt_parent(bt_parent(filename)), bt_arena_cstr_from_sv(&sv));
                        size_t checkpoint = bt_arena_get_checkpoint();
                        if (bt_path_exists(path)) {
                            if (bt_path_is_file(path)) {
                                bt_da_append(&includes, path);
                            } else {
                                bt_arena_rewind(checkpoint);
                            }
                        } else {
                            bt_arena_rewind(checkpoint);
                        }
                        goto end_of_loop;
                    } else {
                        const char* sv_as_cstr = bt_arena_cstr_from_sv(&sv);
                        Bt_String_Array include_paths_to_search = {0};
                        bt_da_append(&include_paths_to_search, bt_parent(filename));
                        bt_da_extend(&include_paths_to_search, &include_paths_to_search_in);

                        size_t i;
                        const char** search_path_;
                        bt_da_foreach_ref(i, search_path_, &include_paths_to_search) {
                            char* full_path = bt_concat_paths(*search_path_, sv_as_cstr);
                            if (bt_path_exists(full_path)) {
                                if (bt_path_is_file(full_path)) {
                                    bt_da_append(&includes, full_path);
                                    goto end_of_loop;
                                }
                            }
                        }
                    }
                }

            end_of_loop:
                contents = p2 + 1;
            }

            bt_sb_free(&sb);
            return includes;
        }

        // please help
        // FIFCFIR: Find If Files Changed From Includes Recursivly (please help)
        typedef struct Bt__FIFCFIR_Entry {
            const char* filepath;
            bool result;
        } Bt__FIFCFIR_Entry;
        typedef struct Bt__FIFCFIR_Table {
            Bt__FIFCFIR_Entry* items;
            size_t size;
            size_t capacity;
        } Bt__FIFCFIR_Table;
        static Bt__FIFCFIR_Table fifcfir_table = {0};
        void bt__fifcfir_table_set(const char* filename, bool result) {
            Bt__FIFCFIR_Entry* entry_ref;
            size_t i;
            bt_da_foreach_ref(i, entry_ref, &fifcfir_table) {
                if (strcmp(filename, entry_ref->filepath) == 0) {
                    entry_ref->result = result;
                    return;
                }
            }
            Bt__FIFCFIR_Entry entry;
            entry.filepath = filename;
            entry.result = result;
            bt_da_append(&fifcfir_table, entry);
        }
        bool bt__fifcfir_contains(const char* filename, bool* value) {
            Bt__FIFCFIR_Entry* entry_ref;
            size_t i;
            bt_da_foreach_ref(i, entry_ref, &fifcfir_table) {
                if (strcmp(filename, entry_ref->filepath) == 0) {
                    if (value != NULL) {
                        *value = entry_ref->result;
                    }
                    return true;
                }
            }
            return false;
        }
        bool find_if_file_changed_from_include_recursivly(const char* target_filepath, Bt_String_Array include_paths_to_search, bool is_gathering) {
            bool possible_result;
            if (bt__fifcfir_contains(target_filepath, &possible_result)) return possible_result;

            Bt_String_Array includes = {0};

            if (!bt_was_file_modified(target_filepath) && bt_include_structure_contains(target_filepath)) {
                includes = bt_include_structure_get(target_filepath);
            } else {
                includes = bt_get_includes_from_file(target_filepath, include_paths_to_search);
                bt_include_structure_update_entry(target_filepath, &includes);
            }

            if (includes.size == 0) {
                bt__fifcfir_table_set(target_filepath, false);
                return false;
            }

            const char* const* include_ref;
            size_t i;
            bt_da_foreach_ref(i, include_ref, &includes) {
                if (!bt__fifcfir_contains(target_filepath, NULL)) {
                    bt__fifcfir_table_set(target_filepath, false);
                }
                if (bt_was_file_modified(*include_ref)) {
                    bt__fifcfir_table_set(target_filepath, true);
                    if (is_gathering) {
                        bt_log_file_update_entry(*include_ref);
                    } else {
                        return true;
                    }
                }

            }
            bt_da_foreach_ref(i, include_ref, &includes) {
                // some company made a header file that includes itself *cough cough google*
                // thus this line was introduced
                if (strcmp(*include_ref, target_filepath) == 0) continue;
                if (find_if_file_changed_from_include_recursivly(*include_ref, include_paths_to_search, is_gathering)) {
                    bt__fifcfir_table_set(target_filepath, true);
                    if (is_gathering) {
                        bt_log_file_update_entry(*include_ref);
                    } else {
                        return true;
                    }
                }

                bt__fifcfir_table_set(target_filepath, false);
            }
            return false;
        }

        bool bt_was_file_modified_from_includes(const char* target_filepath, Bt_String_Array include_paths_to_search) {
            return find_if_file_changed_from_include_recursivly(target_filepath, include_paths_to_search, false);
        }

        bool bt_source_file_needs_rebuild(const char* filename, Bt_String_Array include_directories, Bt_Cmd compile_command) {
            if (bt_was_file_modified(filename)) {
                bt_compile_commands_update_entry(filename, compile_command);
                return true;
            }

            char* object_filename = bt_compiler_source_file_to_object_filename(bt_get_build_directory(), filename);
            if (!bt_path_exists(object_filename)) {
                bt_compile_commands_update_entry(filename, compile_command);
                return true;
            }
            
            if (!bt_compile_commands_is_eq(filename, compile_command)) {
                bt_compile_commands_update_entry(filename, compile_command);
                return true;
            }

            return find_if_file_changed_from_include_recursivly(filename, include_directories, false);
        }

        void bt_save_mtimes(const Bt_Build_Spec* spec) {
            size_t i, j;
            Bt_Static_Library* slib;
            Bt_Executable* executable;

            bt_da_foreach_ref(i, slib, &spec->static_libraries) {
                const char* source_file;
                bt_da_foreach(j, source_file, &slib->sources) {
                    bt_log_file_update_entry(source_file);
                }
            }

            bt_da_foreach_ref(i, executable, &spec->executables) {
                const char* source_file;
                bt_da_foreach(j, source_file, &executable->sources) {
                    bt_log_file_update_entry(source_file);
                }
            }

            fifcfir_table.size = 0;
            bt_da_foreach_ref(i, slib, &spec->static_libraries) {
                const char* source_file;

                Bt_String_Array include_paths_to_search = {0};
                bt_da_extend(&include_paths_to_search, &spec->include_directories);
                bt_da_extend(&include_paths_to_search, &slib->include_directories);

                bt_da_foreach(j, source_file, &slib->sources) {
                    find_if_file_changed_from_include_recursivly(source_file, include_paths_to_search, true);
                }

                bt_da_free(&include_paths_to_search);
            }

            bt_da_foreach_ref(i, executable, &spec->executables) {
                const char* source_file;

                Bt_String_Array include_paths_to_search = {0};
                bt_da_extend(&include_paths_to_search, &spec->include_directories);
                bt_da_extend(&include_paths_to_search, &executable->include_directories);

                bt_da_foreach(j, source_file, &executable->sources) {
                    find_if_file_changed_from_include_recursivly(source_file, include_paths_to_search, true);
                }

                bt_da_free(&include_paths_to_search);
            }
        }

        bool bt_bspec_is_malformed(const Bt_Build_Spec* spec) {
            size_t i;
            const char* path;
            bt_da_foreach(i, path, &spec->include_directories) {
                if (!bt_path_exists(path)) {
                    bt_log(BT_ERROR, "path `%s` does not exist, Bt_Build_Spec.include_directories", path);
                    return true;
                }
                if (!bt_path_is_directory(path)) {
                    bt_log(BT_ERROR, "path `%s` is not a directory, Bt_Build_Spec.include_directories", path);
                    return true;
                }
            }
            bt_da_foreach(i, path, &spec->library_directories) {
                if (!bt_path_exists(path)) {
                    bt_log(BT_ERROR, "path `%s` does not exist, Bt_Build_Spec.library_directories", path);
                    return true;
                }
                if (!bt_path_is_directory(path)) {
                    bt_log(BT_ERROR, "path `%s` is not a directory, Bt_Build_Spec.library_directories", path);
                    return true;
                }
            }

            Bt_Static_Library slib;
            bt_da_foreach(i, slib, &spec->static_libraries) {
                if (!slib.name) {
                    bt_log(BT_ERROR, "static library (index %d) name is null", i);
                    return true;
                }
                if (!slib.output_location) {
                    bt_log(BT_ERROR, "static library `%s` does not have an output location", slib.name);
                    return true;
                }
                if (slib.compile_options & BT_COMPO_OPTIMIZED && slib.compile_options & BT_COMPO_DEBUG_SYMBOLS) {
                    bt_log(BT_ERROR, "static library `%s` has optimizations and debug symbols turned on at the same time", slib.name);
                    return true;
                }
                size_t j;
                const char* file;
                bt_da_foreach(j, file, &slib.sources) {
                    if (!bt_path_exists(file)) {
                        bt_log(BT_ERROR, "file `%s` does not exist, Bt_Build_Spec.static_libraries.<%s>.files", file, slib.name);
                        return true;
                    }
                    if (!bt_path_is_file(file)) {
                        bt_log(BT_ERROR, "path `%s` is not a file, Bt_Build_Spec.static_libraries.<%s>.files", file, slib.name);
                        return true;
                    }
                }
                bt_da_foreach(j, file, &slib.precompiled_headers) {
                    if (!bt_path_exists(file)) {
                        bt_log(BT_ERROR, "file `%s` does not exist, Bt_Build_Spec.static_libraries.<%s>.precompiled_headers", file, slib.name);
                        return true;
                    }
                    if (!bt_path_is_file(file)) {
                        bt_log(BT_ERROR, "path `%s` is not a file, Bt_Build_Spec.static_libraries.<%s>.precompiled_headers", file, slib.name);
                        return true;
                    }
                }
                bt_da_foreach(j, path, &slib.include_directories) {
                    if (!bt_path_exists(path)) {
                        bt_log(BT_ERROR, "path `%s` does not exist, Bt_Build_Spec.<%s>.include_directories", path, slib.name);
                        return true;
                    }
                    if (!bt_path_is_directory(path)) {
                        bt_log(BT_ERROR, "path `%s` is not a directory, Bt_Build_Spec.<%s>.include_directories", path, slib.name);
                        return true;
                    }
                }
                const char* name;
                bt_da_foreach(j, name, &slib.dependencies) {
                    size_t k;
                    Bt_Static_Library other_slib;
                    bool found = true;
                    bt_da_foreach(k, other_slib, &spec->static_libraries) {
                        if (strcmp(name, other_slib.name) == 0) {
                            found = true;
                        }
                    }
                    if (!found) {
                        bt_log(BT_ERROR, "dependency `%s` for static library `%s` does not exist", name, slib.name);
                        return true;
                    }
                }
            }
            Bt_Executable executable;
            bt_da_foreach(i, executable, &spec->executables) {
                if (!executable.name) {
                    bt_log(BT_ERROR, "executable (index %d) name is null", i);
                    return true;
                }
                if (!executable.output_location) {
                    bt_log(BT_ERROR, "executable `%s` does not have an output location", slib.name);
                    return true;
                }
                if (executable.compile_options & BT_COMPO_OPTIMIZED && executable.compile_options & BT_COMPO_DEBUG_SYMBOLS) {
                    bt_log(BT_ERROR, "executable `%s` has optimizations and debug symbols turned on at the same time", slib.name);
                    return true;
                }

                size_t j;
                bt_da_foreach(j, path, &executable.include_directories) {
                    if (!bt_path_exists(path)) {
                        bt_log(BT_ERROR, "path `%s` does not exist, Bt_Build_Spec.executables.<%s>.include_directories", path, slib.name);
                        return true;
                    }
                    if (!bt_path_is_directory(path)) {
                        bt_log(BT_ERROR, "path `%s` is not a directory, Bt_Build_Spec.executables.<%s>.include_directories", path, slib.name);
                        return true;
                    }
                }
                bt_da_foreach(j, path, &executable.precompiled_headers) {
                    if (!bt_path_exists(path)) {
                        bt_log(BT_ERROR, "file `%s` does not exist, Bt_Build_Spec.executables.<%s>.precompiled_headers", path, slib.name);
                        return true;
                    }
                    if (!bt_path_is_file(path)) {
                        bt_log(BT_ERROR, "path `%s` is not a file, Bt_Build_Spec.executables.<%s>.precompiled_headers", path, slib.name);
                        return true;
                    }
                }
                bt_da_foreach(j, path, &executable.library_directories) {
                    if (!bt_path_exists(path)) {
                        bt_log(BT_ERROR, "path `%s` does not exist, Bt_Build_Spec.executables.<%s>.library_directories", path, slib.name);
                        return true;
                    }
                    if (!bt_path_is_directory(path)) {
                        bt_log(BT_ERROR, "path `%s` is not a directory, Bt_Build_Spec.executables.<%s>.library_directories", path, slib.name);
                        return true;
                    }
                }
                Bt_Static_Library other_slib;
                const char* slib_name;
                bt_da_foreach(j, slib_name, &executable.dependencies) {
                    bool found = true;
                    size_t k;
                    bt_da_foreach(k, other_slib, &spec->static_libraries) {
                        if (strcmp(slib_name, other_slib.name) == 0) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        bt_log(BT_ERROR, "static library `%s` does not exist, Bt_Build_Spec.executables.<%s>.static_libraries", slib.name, executable.name);
                        return true;
                    }
                }
            }

            return false;
        }

        int bt_get_cpu_core_count(void) {
            int num_cores = 0;

            #ifdef _WIN32
                SYSTEM_INFO sysinfo;
                GetSystemInfo(&sysinfo);
                num_cores = sysinfo.dwNumberOfProcessors;
            #else
                num_cores = sysconf(_SC_NPROCESSORS_ONLN);
            #endif

            return num_cores;
        }

        int bt__string_in_array(const char* str, const char** array, size_t size) {
            for (size_t i = 0; i < size; i++) {
                if (strcmp(str, array[i]) == 0) {
                    return 1;
                }
            }
            return 0;
        }

        bool bt__slib_in_array(const Bt_Static_Library* slib, const Bt_Static_Libraries slibs) {
            for (size_t i = 0; i < slibs.size; i++) {
                if (strcmp(slib->name, slibs.items[i].name) == 0) {
                    return true;
                }
            }
            return false;
        }

        Bt_Static_Library* bt__get_slib_by_name(Bt_Static_Library* libraries, size_t count, const char* name) {
            for (size_t i = 0; i < count; i++) {
                if (strcmp(name, libraries[i].name) == 0) {
                    return &libraries[i];
                }
            }
            return NULL;
        }

        bool bt_sort_static_libraries(Bt_Static_Library* libraries, size_t count, Bt_Static_Libraries* sorted_libraries) {
            // Create a list of library names
            const char** library_names = malloc(count * sizeof(const char*));
            for (size_t i = 0; i < count; i++) {
                library_names[i] = libraries[i].name;
            }

            // Create a dependency graph
            size_t* in_degree = calloc(count, sizeof(size_t));
            size_t** graph = malloc(count * sizeof(size_t*));
            for (size_t i = 0; i < count; i++) {
                graph[i] = malloc(count * sizeof(size_t));
                for (size_t j = 0; j < count; j++) {
                    graph[i][j] = 0;
                }
            }

            // Build the graph and in-degree count
            for (size_t i = 0; i < count; i++) {
                for (size_t j = 0; j < libraries[i].dependencies.size; j++) {
                    const char* dep = libraries[i].dependencies.items[j];
                    int dep_index = -1;
                    for (size_t k = 0; k < count; k++) {
                        if (strcmp(dep, library_names[k]) == 0) {
                            dep_index = k;
                            break;
                        }
                    }
                    if (dep_index == -1) {
                        bt_log(BT_ERROR, "Unknown static library provided in dependencies");
                        free(library_names);
                        free(in_degree);
                        for (size_t k = 0; k < count; k++) free(graph[k]);
                        free(graph);
                        return false;
                    }
                    graph[dep_index][i] = 1;
                    in_degree[i]++;
                }
            }

            // Find all nodes with no incoming edges
            size_t* queue = malloc(count * sizeof(size_t));
            size_t queue_size = 0;
            for (size_t i = 0; i < count; i++) {
                if (in_degree[i] == 0) {
                    queue[queue_size++] = i;
                }
            }

            // Perform topological sort
            size_t* sorted_indices = malloc(count * sizeof(size_t));
            size_t sorted_size = 0;
            while (queue_size > 0) {
                size_t lib_index = queue[--queue_size];
                sorted_indices[sorted_size++] = lib_index;

                for (size_t i = 0; i < count; i++) {
                    if (graph[lib_index][i]) {
                        in_degree[i]--;
                        if (in_degree[i] == 0) {
                            queue[queue_size++] = i;
                        }
                    }
                }
            }

            // Check for cycles
            if (sorted_size != count) {
                bt_log(BT_ERROR, "Cycle detected in dependencies");
                free(library_names);
                free(in_degree);
                for (size_t i = 0; i < count; i++) free(graph[i]);
                free(graph);
                free(queue);
                free(sorted_indices);
                return false;
            }

            // Build the sorted library array
            for (size_t i = sorted_size; i > 0; i--) {
                bt_da_append(sorted_libraries, libraries[sorted_indices[i - 1]]);
            }

            // Clean up
            free(library_names);
            free(in_degree);
            for (size_t i = 0; i < count; i++) free(graph[i]);
            free(graph);
            free(queue);
            free(sorted_indices);

            return true;
        }

        bool bt_expand_static_libraries_from_strings(Bt_String_Array library_names, Bt_Static_Libraries slibs, Bt_Static_Libraries* out) {
            if (library_names.size == 0) {
                return true;
            }

            Bt_Static_Libraries final_libraries = {0};

            while (library_names.size) {
                const char* strlib = library_names.items[0];
                bt_da_popi(&library_names, 0);

                bool found = false;
                for (size_t i = 0; i < slibs.size; i++) {
                    if (strcmp(slibs.items[i].name, strlib) == 0) {
                        if (!bt__slib_in_array(&slibs.items[i], final_libraries)) {
                            bt_da_append(&final_libraries, slibs.items[i]);
                            bt_da_extend(&library_names, &(slibs.items[i].dependencies));
                        }
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    bt_log(BT_ERROR, "static library `%s` not found", strlib);
                    return false;
                }
            }

            for (size_t i = 0; i < final_libraries.size; i++) {
                bt_da_append(out, final_libraries.items[i]);
            }
            // exit(0);
            return true;
        }
    // END_SECTION: Helpers

    bool bt_init(const char* build_directory) {
        bt_arena_init(1024*1024);

        if (!bt_path_exists(bt_concat_paths(build_directory, ".gitignore"))) {
            if (!bt_mkdir_if_not_exists(build_directory)) {
                return false;
            }
            if (!bt_write_entire_file(bt_concat_paths(build_directory, ".gitignore"), "*\n", 2)) {
                return false;
            }
        }

        bt_set_build_directory(build_directory);

        bt_special_files_init(build_directory);

        return true;
    }

    void bt_shutdown(void) {
        bt_special_files_close(bt_get_build_directory());

        bt_arena_destroy();
    }

    bool bt_build(const Bt_Build_Spec* spec, size_t max_active_processes) {
        BT_ASSERT(max_active_processes > 0 && "max_active_processes must be at least one");
        if (bt_bspec_is_malformed(spec)) {
            bt_log(BT_ERROR, "malformed spec passed to `bt_build`");
            return false;
        }

        // stage 0: compiling pre compiled headers
        // stage 1: compiling object files
        // stage 2: linking static libraries
        // stage 3: linking dynamic libraries
        // stage 4: linking executables
        Bt_Cmds commands_to_execute[5] = {{0}, {0}, {0}, {0}, {0}};

        Bt_String_Array libs_that_will_be_rebuilt = {0};
        
        size_t i;
        Bt_Static_Library* slib;
        bt_da_foreach_ref(i, slib, &spec->static_libraries) {
            Bt_Cmd c_command = {0};
            Bt_Cmd cxx_command = {0};
            bt_da_extend(&c_command, bt_compiler_get_base_c_compile_command());
            bt_da_extend(&cxx_command, bt_compiler_get_base_cxx_compile_command());
            bt_compiler_add_include_directories(&c_command, &slib->include_directories);
            bt_compiler_add_include_directories(&c_command, &spec->include_directories);
            bt_compiler_add_include_directories(&cxx_command, &slib->include_directories);
            bt_compiler_add_include_directories(&cxx_command, &spec->include_directories);

            if (slib->compile_options &BT_COMPO_OPTIMIZED) {
                bt_compiler_turn_on_optimizations(&c_command);
                bt_compiler_turn_on_optimizations(&cxx_command);
            }
            if (slib->compile_options &BT_COMPO_EXTRA_WARNINGS) {
                bt_compiler_enable_all_warnings(&c_command);
                bt_compiler_enable_all_warnings(&cxx_command);
            }
            if (slib->compile_options &BT_COMPO_FAIL_ON_WARNING) {
                bt_compiler_treat_warnings_as_errors(&c_command);
                bt_compiler_treat_warnings_as_errors(&cxx_command);
            }
            if (slib->compile_options &BT_COMPO_DEBUG_SYMBOLS) {
                bt_compiler_generate_debug_symbols(&c_command);
                bt_compiler_generate_debug_symbols(&cxx_command);
            }

            size_t j;
            const char* precompiled_header_name;
            bt_da_foreach(j, precompiled_header_name, &slib->precompiled_headers) {
                Bt_String_View sv = bt_sv_from_cstr(precompiled_header_name);
                if (bt_sv_endswith(sv, ".h")) {
                    bt_compiler_add_precompiled_header(&c_command, precompiled_header_name);
                }
            }
            bt_compiler_add_precompiled_headers(&cxx_command, &slib->precompiled_headers);
            bt_da_extend(&c_command, &slib->extra_build_flags);
            bt_da_extend(&cxx_command, &slib->extra_build_flags);

            Bt_Define* slib_define;
            Bt_Define* global_define;
            size_t k, l;
            bt_da_foreach_ref(k, slib_define, &slib->defines) {
                bt_compiler_add_define(&c_command, slib_define->name, slib_define->value);
                bt_compiler_add_define(&cxx_command, slib_define->name, slib_define->value);
            }
            bt_da_foreach_ref(l, global_define, &spec->extra_defines) {
                bool already_exists = false;
                bt_da_foreach_ref(k, slib_define, &slib->defines) {
                    if (strcmp(global_define->name, slib_define->name) == 0) {
                        already_exists = true;
                        bt_log(BT_WARNING, "macro `%s` already exists, using the one defined by the static library", global_define->name);
                    }
                }
                if (!already_exists) {
                    bt_compiler_add_define(&c_command, global_define->name, global_define->value);
                    bt_compiler_add_define(&cxx_command, global_define->name, global_define->value);
                }
            }

            const char* source_file;
            Bt_String_Array object_files = {0};
            bool need_to_relink_slib = false;

            Bt_String_Array include_paths_to_search = {0};
            bt_da_extend(&include_paths_to_search, &spec->include_directories);
            bt_da_extend(&include_paths_to_search, &slib->include_directories);

            bt_da_foreach(j, source_file, &slib->sources) {
                Bt_Cmd compile_command = {0};

                if (bt_sv_endswith(bt_sv_from_cstr(source_file), ".c")) {
                    bt_da_extend(&compile_command, &c_command);
                } else {
                    bt_da_extend(&compile_command, &cxx_command);
                }

                bt_compiler_no_linking(&compile_command);

                bt_compiler_add_source_file(&compile_command, source_file);
                char* object_filepath = bt_compiler_source_file_to_object_filename(bt_get_build_directory(), source_file);
                bt_compiler_specify_output_name(&compile_command, object_filepath);

                bt_mkdir_parent_if_not_exists(object_filepath);
                bt_da_append(&object_files, object_filepath);

                if (bt_source_file_needs_rebuild(source_file, include_paths_to_search, compile_command)) {
                    compile_command.message = bt_arena_sprintf("compiling %s", source_file);
                    compile_command.fail_message = bt_arena_sprintf("failed to compile %s", source_file);

                    bt_da_append(&commands_to_execute[1], compile_command);
                    need_to_relink_slib = true;
                } else {
                    bt_da_free(&compile_command);
                }
            }

            if (need_to_relink_slib || !bt_path_exists(bt_compiler_get_static_library_name(slib->name, slib->output_location))) {
                bt_da_append(&libs_that_will_be_rebuilt, slib->name);
                
                Bt_Cmd link_command = {0};
                bt_compiler_generate_static_library(&link_command, &object_files, slib->output_location, slib->name);

                bt_mkdir_recursivly_if_not_exists(slib->output_location);

                link_command.message = bt_arena_sprintf("creating static library %s", slib->name);
                link_command.fail_message = bt_arena_sprintf("failed to create static library %s", slib->name);

                bt_da_append(&commands_to_execute[2], link_command);
            }

            bt_da_free(&object_files);
            bt_da_free(&c_command);
            bt_da_free(&cxx_command);
            bt_da_free(&include_paths_to_search);
        }

        Bt_Executable* executable;
        bt_da_foreach_ref(i, executable, &spec->executables) {
            Bt_Cmd c_command = {0};
            Bt_Cmd cxx_command = {0};
            bt_da_extend(&c_command, bt_compiler_get_base_c_compile_command());
            bt_da_extend(&cxx_command, bt_compiler_get_base_cxx_compile_command());
            bt_compiler_add_include_directories(&c_command, &executable->include_directories);
            bt_compiler_add_include_directories(&c_command, &spec->include_directories);
            bt_compiler_add_include_directories(&cxx_command, &executable->include_directories);
            bt_compiler_add_include_directories(&cxx_command, &spec->include_directories);

            if (executable->compile_options &BT_COMPO_OPTIMIZED) {
                bt_compiler_turn_on_optimizations(&c_command);
                bt_compiler_turn_on_optimizations(&cxx_command);
            }
            if (executable->compile_options &BT_COMPO_EXTRA_WARNINGS) {
                bt_compiler_enable_all_warnings(&c_command);
                bt_compiler_enable_all_warnings(&cxx_command);
            }
            if (executable->compile_options &BT_COMPO_FAIL_ON_WARNING) {
                bt_compiler_treat_warnings_as_errors(&c_command);
                bt_compiler_treat_warnings_as_errors(&cxx_command);
            }
            if (executable->compile_options &BT_COMPO_DEBUG_SYMBOLS) {
                bt_compiler_generate_debug_symbols(&c_command);
                bt_compiler_generate_debug_symbols(&cxx_command);
            }

            size_t j;
            const char* precompiled_header_name;
            bt_da_foreach(j, precompiled_header_name, &executable->precompiled_headers) {
                Bt_String_View sv = bt_sv_from_cstr(precompiled_header_name);
                if (bt_sv_endswith(sv, ".h")) {
                    bt_compiler_add_precompiled_header(&c_command, precompiled_header_name);
                }
            }
            bt_compiler_add_precompiled_headers(&cxx_command, &executable->precompiled_headers);
            bt_da_extend(&c_command, &executable->extra_build_flags);
            bt_da_extend(&cxx_command, &executable->extra_build_flags);

            Bt_Define* executable_define;
            Bt_Define* global_define;
            size_t k, l;
            bt_da_foreach_ref(k, executable_define, &executable->defines) {
                bt_compiler_add_define(&c_command, executable_define->name, executable_define->value);
                bt_compiler_add_define(&cxx_command, executable_define->name, executable_define->value);
            }
            bt_da_foreach_ref(l, global_define, &spec->extra_defines) {
                bool already_exists = false;
                bt_da_foreach_ref(k, executable_define, &executable->defines) {
                    if (strcmp(global_define->name, executable_define->name) == 0) {
                        already_exists = true;
                        bt_log(BT_WARNING, "macro `%s` already exists, using the one defined by the executable", global_define->name);
                    }
                }
                if (!already_exists) {
                    bt_compiler_add_define(&c_command, global_define->name, global_define->value);
                    bt_compiler_add_define(&cxx_command, global_define->name, global_define->value);
                }
            }

            Bt_String_Array include_paths_to_search = {0};
            bt_da_extend(&include_paths_to_search, &spec->include_directories);
            bt_da_extend(&include_paths_to_search, &executable->include_directories);

            const char* source_file;
            Bt_String_Array object_files = {0};
            bool need_to_relink_executable = false;
            bt_da_foreach(j, source_file, &executable->sources) {
                Bt_Cmd compile_command = {0};

                if (bt_sv_endswith(bt_sv_from_cstr(source_file), ".c")) {
                    bt_da_extend(&compile_command, &c_command);
                } else {
                    bt_da_extend(&compile_command, &cxx_command);
                }

                bt_compiler_no_linking(&compile_command);

                bt_compiler_add_source_file(&compile_command, source_file);
                char* object_filepath = bt_compiler_source_file_to_object_filename(bt_get_build_directory(), source_file);
                bt_compiler_specify_output_name(&compile_command, object_filepath);
                bt_mkdir_parent_if_not_exists(object_filepath);

                bt_da_append(&object_files, object_filepath);

                if (bt_source_file_needs_rebuild(source_file, include_paths_to_search, compile_command)) {
                    compile_command.message = bt_arena_sprintf("compiling %s", source_file);
                    compile_command.fail_message = bt_arena_sprintf("failed to compile %s", source_file);
                    bt_da_append(&commands_to_execute[1], compile_command);
                    need_to_relink_executable = true;
                } else {
                    bt_da_free(&compile_command);
                }
            }
            bt_da_free(&c_command);
            bt_da_free(&cxx_command);
            bt_da_free(&include_paths_to_search);

            const char* final_exe_name = bt_concat_paths(executable->output_location, bt_arena_sprintf("%s%s", executable->name, bt_compiler_get_executable_extension()));
            
            bool was_a_dependency_modified = false;
            
            Bt_Static_Libraries expanded_libraries = {0};
            if (!bt_expand_static_libraries_from_strings(executable->dependencies, spec->static_libraries, &expanded_libraries)) {
                bt_log(BT_ERROR, "error found in the dependencies while processing `%s` executable", executable->name);
                return false;
            }

            Bt_Static_Libraries sorted_libraries = {0};
            if (!bt_sort_static_libraries(expanded_libraries.items, expanded_libraries.size, &sorted_libraries)) {
                bt_log(BT_ERROR, "error found in the dependencies while processing %s executable", executable->name);
                return false;
            }
            
            for (size_t i = 0; i < sorted_libraries.size; i++) {
                for (size_t j = 0; j < libs_that_will_be_rebuilt.size; j++) {
                    if (strcmp(sorted_libraries.items[i].name, libs_that_will_be_rebuilt.items[j]) == 0) {
                        was_a_dependency_modified = true;
                        break;
                    }
                }
            }
            
            if (need_to_relink_executable || !bt_path_exists(final_exe_name) || was_a_dependency_modified) {
                Bt_Cmd link_command = {0};
                bt_da_extend(&link_command, bt_compiler_get_base_linker_command());
                bt_compiler_add_files_to_linker(&link_command, &object_files);
                bt_compiler_add_library_directories(&link_command, &executable->library_directories);
                bt_compiler_add_libraries(&link_command, &executable->libraries);
                bt_compiler_add_library_directories(&link_command, &spec->library_directories);
                bt_compiler_add_libraries(&link_command, &spec->libraries);
                for (size_t k = 0; k < sorted_libraries.size; k++) {
                    bt_compiler_add_library(&link_command, sorted_libraries.items[k].name);
                    bt_compiler_add_library_directory(&link_command, sorted_libraries.items[k].output_location);
                }

                char* executable_name = bt_concat_paths(executable->output_location, executable->name);
                executable_name = bt_arena_strcat(executable_name, bt_compiler_get_executable_extension());

                bt_compiler_specify_output_name(&link_command, executable_name);

                link_command.message = bt_arena_sprintf("linking executable %s", executable->name);
                link_command.fail_message = bt_arena_sprintf("failed to link %s", executable->name);

                bt_da_append(&commands_to_execute[3], link_command);
            }
            bt_da_free(&object_files);
        }

        if (!bt_execute_command_queue(commands_to_execute, 5, max_active_processes)) {
            return false;
        }

        bt_sb_free(&commands_to_execute[0]);
        bt_sb_free(&commands_to_execute[1]);
        bt_sb_free(&commands_to_execute[2]);
        bt_sb_free(&commands_to_execute[3]);
        bt_sb_free(&commands_to_execute[4]);

        bt_save_mtimes(spec);

        return true;
    }

    void bt_rebuild_self_if_needed(const char* source_file, const char* output_location, const char* final_executable_name) {
        Bt_String_Array incs = {0};
        if (!bt_was_file_modified(source_file) && !bt_was_file_modified_from_includes(source_file, incs)) {
            return;
        }
        bt_log(BT_INFO, "rebuilding self");
        Bt_Build_Spec spec = {0};
        
        bt_mkdir_if_not_exists(output_location);

        char* temp_executable_name = strdup(bt_arena_strcat(final_executable_name, ".temp"));
        char* temp_executable_name_ext = strdup(bt_arena_strcat(temp_executable_name, bt_compiler_get_executable_extension()));

        Bt_Executable executable = {0};
        bt_exe_set_name(&executable, temp_executable_name);
        bt_exe_set_output_location(&executable, output_location);
        bt_exe_add_source(&executable, source_file);
        executable.compile_options = BT_COMPO_DEBUG_SYMBOLS;

        bt_da_append(&spec.executables, executable);

        char* final_executable_ext = strdup(
            bt_concat_paths(output_location, bt_arena_sprintf("%s%s", final_executable_name, bt_compiler_get_executable_extension()))
        );

        if (!bt_build(&spec, bt_get_cpu_core_count())) {
            bt_shutdown();
            free(final_executable_ext);
            free(temp_executable_name);
            free(temp_executable_name_ext);
            exit(1);
        }
        free(temp_executable_name_ext);

        char* temp_exe = strdup(bt_concat_paths(output_location, bt_arena_strcat(temp_executable_name, bt_compiler_get_executable_extension())));
        
        bt_shutdown();
        bt_sleep(50);
        
        #ifdef _WIN32
            if (!MoveFileEx(temp_exe, final_executable_ext, MOVEFILE_REPLACE_EXISTING)) {
                bt_log(BT_ERROR, "could not rename %s to %s: %s", temp_exe, final_executable_ext, bt_win32_error_message(GetLastError()));
                exit(1);
            }
        #else
            if (rename(temp_exe, final_executable_ext) < 0) {
                bt_log(BT_ERROR, "could not rename %s to %s: %s", temp_exe, final_executable_ext, strerror(errno));
                exit(1);
            }
        #endif // _WIN32

        int retcode;
        if (!bt_execute_command(&retcode, NULL, final_executable_ext)) {
            free(final_executable_ext);
            free(temp_executable_name);
            free(temp_exe);
            exit(1);
        }
        free(final_executable_ext);
        free(temp_executable_name);
        free(temp_exe);
        exit(retcode);
    }
    
    bool bt_dump_compile_commands_json(const Bt_Build_Spec* spec, const char* compile_commands_json_path) {
        // the `message` filed is treated as the filename
        Bt_Cmds commands = {0};
        
        size_t i;
        Bt_Static_Library* slib;
        bt_da_foreach_ref(i, slib, &spec->static_libraries) {
            Bt_Cmd c_command = {0};
            Bt_Cmd cxx_command = {0};
            bt_da_extend(&c_command, bt_compiler_get_base_c_compile_command());
            bt_da_extend(&cxx_command, bt_compiler_get_base_cxx_compile_command());
            bt_compiler_add_include_directories(&c_command, &slib->include_directories);
            bt_compiler_add_include_directories(&c_command, &spec->include_directories);
            bt_compiler_add_include_directories(&cxx_command, &slib->include_directories);
            bt_compiler_add_include_directories(&cxx_command, &spec->include_directories);

            if (slib->compile_options &BT_COMPO_OPTIMIZED) {
                bt_compiler_turn_on_optimizations(&c_command);
                bt_compiler_turn_on_optimizations(&cxx_command);
            }
            if (slib->compile_options &BT_COMPO_EXTRA_WARNINGS) {
                bt_compiler_enable_all_warnings(&c_command);
                bt_compiler_enable_all_warnings(&cxx_command);
            }
            if (slib->compile_options &BT_COMPO_FAIL_ON_WARNING) {
                bt_compiler_treat_warnings_as_errors(&c_command);
                bt_compiler_treat_warnings_as_errors(&cxx_command);
            }
            if (slib->compile_options &BT_COMPO_DEBUG_SYMBOLS) {
                bt_compiler_generate_debug_symbols(&c_command);
                bt_compiler_generate_debug_symbols(&cxx_command);
            }

            size_t j;
            const char* precompiled_header_name;
            bt_da_foreach(j, precompiled_header_name, &slib->precompiled_headers) {
                Bt_String_View sv = bt_sv_from_cstr(precompiled_header_name);
                if (bt_sv_endswith(sv, ".h")) {
                    bt_compiler_add_precompiled_header(&c_command, precompiled_header_name);
                }
            }
            bt_compiler_add_precompiled_headers(&cxx_command, &slib->precompiled_headers);
            bt_da_extend(&c_command, &slib->extra_build_flags);
            bt_da_extend(&cxx_command, &slib->extra_build_flags);

            Bt_Define* slib_define;
            Bt_Define* global_define;
            size_t k, l;
            bt_da_foreach_ref(k, slib_define, &slib->defines) {
                bt_compiler_add_define(&c_command, slib_define->name, slib_define->value);
                bt_compiler_add_define(&cxx_command, slib_define->name, slib_define->value);
            }
            bt_da_foreach_ref(l, global_define, &spec->extra_defines) {
                bool already_exists = false;
                bt_da_foreach_ref(k, slib_define, &slib->defines) {
                    if (strcmp(global_define->name, slib_define->name) == 0) {
                        already_exists = true;
                    }
                }
                if (!already_exists) {
                    bt_compiler_add_define(&c_command, global_define->name, global_define->value);
                    bt_compiler_add_define(&cxx_command, global_define->name, global_define->value);
                }
            }

            const char* source_file;
            bool need_to_relink_slib = false;

            Bt_String_Array include_paths_to_search = {0};
            bt_da_extend(&include_paths_to_search, &spec->include_directories);
            bt_da_extend(&include_paths_to_search, &slib->include_directories);

            bt_da_foreach(j, source_file, &slib->sources) {
                Bt_Cmd compile_command = {0};

                if (bt_sv_endswith(bt_sv_from_cstr(source_file), ".c")) {
                    bt_da_extend(&compile_command, &c_command);
                } else {
                    bt_da_extend(&compile_command, &cxx_command);
                }

                bt_compiler_no_linking(&compile_command);

                bt_compiler_add_source_file(&compile_command, source_file);
                char* object_filepath = bt_compiler_source_file_to_object_filename(bt_get_build_directory(), source_file);
                bt_compiler_specify_output_name(&compile_command, object_filepath);

                compile_command.message = source_file;
                bt_da_append(&commands, compile_command);
            }

            bt_da_free(&c_command);
            bt_da_free(&cxx_command);
            bt_da_free(&include_paths_to_search);
        }

        Bt_Executable* executable;
        bt_da_foreach_ref(i, executable, &spec->executables) {
            Bt_Cmd c_command = {0};
            Bt_Cmd cxx_command = {0};
            bt_da_extend(&c_command, bt_compiler_get_base_c_compile_command());
            bt_da_extend(&cxx_command, bt_compiler_get_base_cxx_compile_command());
            bt_compiler_add_include_directories(&c_command, &executable->include_directories);
            bt_compiler_add_include_directories(&c_command, &spec->include_directories);
            bt_compiler_add_include_directories(&cxx_command, &executable->include_directories);
            bt_compiler_add_include_directories(&cxx_command, &spec->include_directories);

            if (executable->compile_options &BT_COMPO_OPTIMIZED) {
                bt_compiler_turn_on_optimizations(&c_command);
                bt_compiler_turn_on_optimizations(&cxx_command);
            }
            if (executable->compile_options &BT_COMPO_EXTRA_WARNINGS) {
                bt_compiler_enable_all_warnings(&c_command);
                bt_compiler_enable_all_warnings(&cxx_command);
            }
            if (executable->compile_options &BT_COMPO_FAIL_ON_WARNING) {
                bt_compiler_treat_warnings_as_errors(&c_command);
                bt_compiler_treat_warnings_as_errors(&cxx_command);
            }
            if (executable->compile_options &BT_COMPO_DEBUG_SYMBOLS) {
                bt_compiler_generate_debug_symbols(&c_command);
                bt_compiler_generate_debug_symbols(&cxx_command);
            }

            size_t j;
            const char* precompiled_header_name;
            bt_da_foreach(j, precompiled_header_name, &executable->precompiled_headers) {
                Bt_String_View sv = bt_sv_from_cstr(precompiled_header_name);
                if (bt_sv_endswith(sv, ".h")) {
                    bt_compiler_add_precompiled_header(&c_command, precompiled_header_name);
                }
            }
            bt_compiler_add_precompiled_headers(&cxx_command, &executable->precompiled_headers);
            bt_da_extend(&c_command, &executable->extra_build_flags);
            bt_da_extend(&cxx_command, &executable->extra_build_flags);

            Bt_Define* executable_define;
            Bt_Define* global_define;
            size_t k, l;
            bt_da_foreach_ref(k, executable_define, &executable->defines) {
                bt_compiler_add_define(&c_command, executable_define->name, executable_define->value);
                bt_compiler_add_define(&cxx_command, executable_define->name, executable_define->value);
            }
            bt_da_foreach_ref(l, global_define, &spec->extra_defines) {
                bool already_exists = false;
                bt_da_foreach_ref(k, executable_define, &executable->defines) {
                    if (strcmp(global_define->name, executable_define->name) == 0) {
                        already_exists = true;
                        bt_log(BT_WARNING, "macro `%s` already exists, using the one defined by the executable", global_define->name);
                    }
                }
                if (!already_exists) {
                    bt_compiler_add_define(&c_command, global_define->name, global_define->value);
                    bt_compiler_add_define(&cxx_command, global_define->name, global_define->value);
                }
            }

            Bt_String_Array include_paths_to_search = {0};
            bt_da_extend(&include_paths_to_search, &spec->include_directories);
            bt_da_extend(&include_paths_to_search, &executable->include_directories);

            const char* source_file;
            bool need_to_relink_executable = false;
            bt_da_foreach(j, source_file, &executable->sources) {
                Bt_Cmd compile_command = {0};

                if (bt_sv_endswith(bt_sv_from_cstr(source_file), ".c")) {
                    bt_da_extend(&compile_command, &c_command);
                } else {
                    bt_da_extend(&compile_command, &cxx_command);
                }

                bt_compiler_no_linking(&compile_command);

                bt_compiler_add_source_file(&compile_command, source_file);
                char* object_filepath = bt_compiler_source_file_to_object_filename(bt_get_build_directory(), source_file);
                bt_compiler_specify_output_name(&compile_command, object_filepath);
                bt_mkdir_parent_if_not_exists(object_filepath);

                compile_command.message = source_file;
                bt_da_append(&commands, compile_command);
            }
            bt_da_free(&c_command);
            bt_da_free(&cxx_command);
            bt_da_free(&include_paths_to_search);
        }
        
        char* cwd = NULL;
        #ifdef BT_WINDOWS
            DWORD bufferSize = GetCurrentDirectory(0, NULL); // Get required buffer size
            if (bufferSize == 0) {
                fprintf(stderr, "GetCurrentDirectory failed: %s", bt_win32_error_message(GetLastError()));
                return false;
            }
        
            cwd = (char*)bt_arena_malloc(bufferSize * sizeof(char));
        
            if (GetCurrentDirectory(bufferSize, cwd) == 0) {
                fprintf(stderr, "GetCurrentDirectory failed: %s", bt_win32_error_message(GetLastError()));
                bt_arena_free(cwd);
                return false;
            }
        #else // BT_WINDOWS
            size_t cwd_size = 8;
            cwd = (char*)bt_arena_malloc(cwd_size * sizeof(char));
            
            while (getcwd(cwd, cwd_size) == NULL) {
                if (errno == ERANGE) {
                    cwd_size *= 2;
                    bt_arena_free(cwd);
                    cwd = (char*)bt_arena_malloc(cwd_size * sizeof(char));
                } else {
                bt_log(BT_ERROR, "getcwd failed: %s", strerror(errno));
                return false;
                }
            }
        #endif // BT_WINDOWS
        
        
        bt_mkdir_parent_if_not_exists(compile_commands_json_path);        
        FILE* file = fopen(compile_commands_json_path, "w"); 
        if (file == NULL) {
            bt_log(BT_ERROR, "failed to open file `%s`", compile_commands_json_path);
            return false;
        }
        Jim jim = {
            .sink = file,
            .write = (Jim_Write) fwrite,
        };
    
        jim_array_begin(&jim);

        for (i = 0; i < commands.size; i++) {
            Bt_Cmd cmd = commands.items[i];
            
            jim_object_begin(&jim);
            
            jim_member_key(&jim, "directory");
            jim_string(&jim, cwd);
            
            jim_member_key(&jim, "arguments");
            jim_array_begin(&jim);
            for (size_t j = 0; j < cmd.size; j++) {
                jim_string(&jim, cmd.items[j]);
            }
            jim_array_end(&jim);
            
            jim_member_key(&jim, "file");
            jim_string(&jim, cmd.message);
            
            jim_object_end(&jim);
        }
        
        jim_array_end(&jim);
    
        if (jim.error != JIM_OK) {
            fprintf(stderr, "ERROR: could not serialize json properly: %s\n",
                    jim_error_string(jim.error));
            return false;
        }
        
        fclose(file);
        return true;
    }
    
// END_SECTION: BuildSys

#endif // BUILDIT_IMPLEMENTATION
