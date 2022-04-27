/* gcc -shared -fPIC -o rebase_lib.so rebase_lib.c */

int foo(int value){
    if(value == 0xdead){
        return 1;
    }
    else {
        return 0;
    }
}
