#include <Windows.h>

#define Icarus_API __declspec(dllexport)

typedef struct https {
    BOOL get_post;     
    BOOL file_switch;   
    char *msg;          
    char *postfile;  
    char *server;    
    char *fileserver;   
    char *files;        
} https_t;

