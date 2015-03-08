#include "pass_db.h"
#include "pass_defines.h"

// Global variables shared across all commands

char password[MAX_PASS_LENGTH];
int error_code = 0;
db_handle_t handle;

// Get pass moved to seperate function for cleaner code in main function

void prompt_pass()
{
    memset(password, 0, MAX_PASS_LENGTH);
    printf("\nEnter this database's password\n$ ");
    fgets(password, MAX_PASS_LENGTH, stdin);
    password[strlen(password) - 1] = '\0';
}

void print_help()
{
    printf("\nUsage:\n");
    printf("    <program> <command> <filename>\n");
    printf("    <program> <command> <filename> <passwordname>\n\n");

    printf("Commands:\n");
    printf("    create : Create a new password database\n");
    printf("    add    : Add a new password to the database\n");
    printf("    remove : Remove a password from the database\n");
    printf("    get    : Get a password from the database\n");
    printf("    list   : List all passwords in the database\n");
    printf("    info   : Get info about the database\n");
    printf("    help   : Print help page\n\n");
    
    printf("Examples:\n");
    printf("    <program> create password_db\n");
    printf("    <program> info password_db\n");
    printf("    <program> add password_db email_password\n");
    printf("    <program> get password_db email_password\n");
}

void handle_errors(int error_code)
{
    switch(error_code)
    {
        case DB_FILE_NOT_FOUND:
            printf("\nA file with that name could not be found\n\n");
            break;
        case DB_BAD_FILE_SIZE:
            printf("\nThis file is not a valid password database\n\n");
            break;
        case DB_BAD_MAGIC:
            printf("\nThis file is not a valid password database or your password is incorrect\n\n");
            break;
        case DB_FILE_OPEN_ERROR:
            printf("\nAn error occured when opening the database\n\n");
            break;
        case DB_FILE_EXISTS:
            printf("\nA file with that name already exists\n\n");
            break;
        case DB_RECORD_EXISTS:
            printf("\nThis database already has a record with that name\n\n");
            break;
        case DB_RECORD_NOT_FOUND:
            printf("\nA record with that name could not be found\n\n");
            break;
        case DB_RECORD_LIMIT_REACHED:
            printf("\nThis database has reached its maximum capacity (1000 records)\n\n");
            break;
        case DB_NO_RECORDS:
            printf("\nThis database has no records in it\n\n");
            break;
    }
}

int main(int argc, char **argv)
{
    char *commands[] = { "create", "get", "add", "remove", "list", "info" };
    int num_comms = 6;

    init_gcrypt();
    
    if(argc == 2 && strcmp(argv[1], "help") == 0)
    {
        print_help();
        return 0;
    }
    
    // Check for valid amount of arguments

    if(argc > 4 || argc < 3)
    {
        printf("\nError: Invalid command\nType '<program> help' to get list of commands and proper usage\n\n");
        return 1;
    }
    
    int error_code = 0;
    db_handle_t handle;
    
    if(strcmp(argv[1], "create") == 0)
    {
        if(argc != 3)
        {
            printf("\nError: Invalid command\nType '<program> help' to get list of commands and proper usage\n\n");
            return 1;
        }

        prompt_pass();
        if(error_code = create_pass_db(argv[2], password, &handle))
        {
            handle_errors(error_code);
            return 1;
        }
        else
        {
            printf("\nDatabase successfully created\n\n");
            close_handle(&handle);
            return 0;
        }
    }
    else if(strcmp(argv[1], "get") == 0)
    {
        if(argc != 4)
        {
            printf("\nError: Invalid command\nType '<program> help' to get list of commands and proper usage\n\n");
            return 1;
        }

        prompt_pass();
        if(error_code = open_pass_db(argv[2], password, &handle))
        {
            handle_errors(error_code);
            return 1;
        }
        else
        {
            char *output = get_pass(argv[3], &handle);
            if(output)
            {
                printf("\n%s\n\n", output);
                memset(output, 0, sizeof(output));
                close_handle(&handle);
                return 0;
            }
            else
            {
                printf("\nA record with that name was not found\n\n");
                close_handle(&handle);
                return 1;
            }
        }
    }
    else if(strcmp(argv[1], "add") == 0)
    {
        if(argc != 4)
        {
            printf("\nError: Invalid command\nType '<program> help' to get list of commands and proper usage\n\n");
            return 1;
        }

        prompt_pass();
        if(error_code = open_pass_db(argv[2], password, &handle))
        {
            handle_errors(error_code);
            return 1;
        }
        else
        {
            /** Need to check if input is a number **/

            int pass_size;
            printf("\nHow long would you like this password to be?\n");
            printf("(Maximum 10000 characters)\n$ ");
            scanf("%d", &pass_size);

            while(pass_size > 10000)
            {
                printf("\nPasswords can't be over 10000 characters long\n");
                printf("Please enter a smaller value\n$ ");
                scanf("%d", &pass_size);
            }

            if(error_code = create_db_record(argv[3], pass_size, &handle))
            {
                handle_errors(error_code);
                close_handle(&handle);
                return 1;
            }
            else
            {
                printf("\nPassword successfully added to database\n\n");
                close_handle(&handle);
                return 0;
            }
        }
    }
    else if(strcmp(argv[1], "remove") == 0)
    {
        if(argc != 4)
        {
            printf("\nError: Invalid command\nType '<program> help' to get list of commands and proper usage\n\n");
            return 1;
        }

        prompt_pass();
        if(error_code = open_pass_db(argv[2], password, &handle))
        {
            handle_errors(error_code);
            return 1;
        }
        else
        {
            if(error_code = delete_db_record(argv[3], &handle))
            {
                handle_errors(error_code);
                return 1;
            }
                
            printf("\nPassword successfully removed from database\n\n");
            close_handle(&handle);
            return 0;
        }
    }
    else if(strcmp(argv[1], "list") == 0)
    {
        prompt_pass();
        if(error_code = open_pass_db(argv[2], password, &handle))
        {
            handle_errors(error_code);
            return 1;
        }
        else
        {
            if(error_code = list_records(&handle))
            {
                handle_errors(error_code);
                close_handle(&handle);
                return 1;
            }
            else
            {
                close_handle(&handle);
                return 0;
            }
        }
    }
    else if(strcmp(argv[1], "info") == 0)
    {
        prompt_pass();
        if(error_code = open_pass_db(argv[2], password, &handle))
        {
            handle_errors(error_code);
            return 1;
        }
        else
        {
            print_db_info(&handle);
            return 0;
        }
    }
    else
    {
        printf("\nError: Invalid command\nType '<program> help' to get list of commands and proper usage\n\n");
        return 1;
    }
    
    return 0;
}
