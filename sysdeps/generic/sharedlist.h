#define SHARED_LIST_SIZE 2
#ifndef NO_SHARED_LIST
char shared_list[SHARED_LIST_SIZE][30] = 
{
"libc.so.6",
"test.so",
};
#endif