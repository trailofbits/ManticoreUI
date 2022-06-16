#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

/* gcc -o rebase_harness rebase_harness.c -ldl -no-pie */

int main(int argc, char **argv){
    if(argc < 3){
        puts("Usage: rebase_harness <lib_path> <value>");
        exit(1);
    }

    char *library_name = argv[1];
    int value = atoi(argv[2]);

    void *handle = dlopen(library_name, RTLD_LAZY);
    if(!handle){
        puts(dlerror());
        exit(1);
    }

    int (*foo)(int);
    foo = dlsym(handle, "foo");
    if(!foo){
        exit(1);
    }

    if(foo(value)){
        puts("Yes");
    }
    else{
        puts("No");
    }

    return 0;
}
