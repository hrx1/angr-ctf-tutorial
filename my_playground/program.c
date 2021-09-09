#include<stdio.h>
#include<string.h>

int main()
{
    printf("DOBRODOSAO!\n");
    char buffer[1024];
    FILE * fd = fopen("datoteka", "r");

    fread(buffer, 11, 1, fd);

    if(strncmp(buffer, "ovojesifra!", 11) == 0) {
        printf("Good Job.\n");
    } else {
        printf("Try Again.\n");
    }
    fclose(fd);
    return 0;
}