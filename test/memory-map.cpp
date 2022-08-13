#include <zkinject/zkprocess.hh>
#include <zkinject/zklog.hh>
#include <wait.h>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Expected a process\n");
        return -1;
    }
    char *s[2];
    s[0] = argv[1];
    s[1] = nullptr;

    pid_t pid = fork();
    if (pid == 0) {
        
    } else if (pid > 0) {
        
    }
}
