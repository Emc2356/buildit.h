# Buildit.h
buildit is a tool for building simple C projects. It is not a build system that aims to compete with CMake but an extension of rexim's idea of [Nob.h](https://github.com/tsoding/nob.h).

# Features
- [X] incremental builds  
- [X] Static Libraries  
- [X] Executables  
- [X] Clang compiler  
- [X] Gnu compiler  
- [X] Rebuilds if includes changed (does not have a preprocessor)  
- [X] Rebuilds if a flag changes  
- [X] able to generate compile_commands.json for lsp  
- [ ] MSVC compiler  
- [ ] Pre-compiled headers  
- [ ] Dynamic Libraries  

# Dependencies
NOTE: since Buildit.h is a headers only library the dependencies are embeded into the header  
- [jim](https://github.com/tsoding/jim) for dumping the json file for the lsp
- [subprocess.h](https://github.com/sheredom/subprocess.h) for creating and managing async subprocesses
- [Nob.h](https://github.com/tsoding/nob.h) small snippets where taken from nob.h
- [arena.h](https://github.com/Emc2356/arena.h) for arena allocators

# Example
building GLFW with buildit.h  
contents of build.c:
```c
#define BUILDIT_IMPLEMENTATION
#include "buildit.h"

void glfw_add_slib(Bt_Build_Spec* spec, const char* glfw_path, const char* output_location, const char** include_directory) {
    Bt_Static_Library* glfw = bt_arena_calloc(1, sizeof(*glfw));
    bt_slib_set_name(glfw, "glfw");
    bt_slib_set_output_location(glfw, output_location);
    
    bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/context.c"));
    bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/init.c"));
    bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/input.c"));
    bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/monitor.c"));
    bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/null_init.c"));
    bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/null_joystick.c"));
    bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/null_monitor.c"));
    bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/null_window.c"));
    bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/platform.c"));
    bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/vulkan.c"));
    bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/window.c"));
    
    #if defined(BT_WINDOWS)
        bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/win32_init.c"));
        bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/win32_joystick.c"));
        bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/win32_module.c"));
        bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/win32_monitor.c"));
        bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/win32_time.c"));
        bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/win32_thread.c"));
        bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/win32_window.c"));
        bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/wgl_context.c"));
        bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/egl_context.c"));
        bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/osmesa_context.c"));
        bt_slib_add_define(glfw, "_GLFW_WIN32", NULL);
    #elif defined(BT_LINUX)
        bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/x11_init.c"));
        bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/x11_monitor.c"));
        bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/x11_window.c"));
        bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/xkb_unicode.c"));
        bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/posix_module.c"));
        bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/posix_time.c"));
        bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/posix_thread.c"));
        bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/posix_module.c"));
        bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/posix_poll.c"));
        bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/glx_context.c"));
        bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/egl_context.c"));
        bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/osmesa_context.c"));
        bt_slib_add_source(glfw, bt_concat_paths(glfw_path, "src/linux_joystick.c"));
        bt_slib_add_define(glfw, "_GLFW_X11", NULL);
    #endif // BT_WINDOWS 
    
    glfw->compile_options = BT_COMPO_OPTIMIZED;
    *include_directory = bt_concat_paths(glfw_path, "include");
    
    bt_bspec_add_static_library(spec, glfw);
}

int main(void) {
    // the build directory is automatically gitignored
    bt_init("./build/clang");
    //                               [c-standard] [cpp-standard]
    bt_compiler_set(bt_create_clang_compiler(NULL, NULL));
    
    //                 [this-file] [output-location] [executable-name]
    bt_rebuild_self_if_needed("build.c", ".", "build");
    
    Bt_Build_Spec spec = {0};
    
    const char* glfw_include_dir;
    glfw_add_slib(&spec, "./ext/glfw", "./build/libraries/", &glfw_include_dir);
    
    //        [Build-Specification] [max-active-processes]
    if (!bt_build(&spec, bt_get_cpu_core_count())) {
        bt_log(BT_ERROR, "build failed");
        return 1;
    }

    if (!bt_dump_compile_commands_json(&spec, "./compile_commands.json")) {
        bt_log(BT_ERROR, "failed to generate compile_commands.json");
        return 1;
    }
    
    // !!!IMPORTANT!!! if this is missing then buildit.h will keep recompiling everything over and over again
    bt_shutdown();
    
    return 0;
}

```
to run the above code you need to git clone [GLFW](https://github.com/glfw/glfw) into ext/glfw and run the following commands:  
Linux: 
```bash
cc build.c -o build.out
./build.out
```
Windows:
```bash
clang build.c -o build.exe
./build.exe
```