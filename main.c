#include "pass_db.h"
#include "pass_defines.h"

void print_help()
{
	printf("\nUsage:\n");
	printf("    <program> <command> <filename>\n");
    printf("    <program> <command> <filename> <passwordname>\n\n");

    /*
    printf("With database password as argument:\n");
    printf("    <program> -p <db_password> <command> <filename>\n");
    printf("    <program> <command> <filename> -p <db_password>\n\n");
    */

	printf("Commands:\n");
	printf("    create : Create a new password database\n");
	printf("    add    : Add a new password to the database\n");
	printf("    remove : Remove a password from the database\n");
	printf("    get    : Get a password from the database\n");
	printf("    list   : List all passwords in the database\n");
	printf("    help   : Print help page\n\n");
	
	printf("Examples:\n");
	printf("    <program> create password_db\n");
    printf("    <program> add password_db email_password\n");
    //printf("    <program> -p my_password list password_db\n");
    //printf("    <program> get password_db email_password -p my_password\n\n");
}

void handle_errors(int error_code)
{
	switch(error_code)
	{
		case DB_FILE_NOT_FOUND:
            printf("\nA file with that name could not be found\n");
			break;
		case DB_BAD_FILE_SIZE:
            printf("\nThis file is not a valid password database\n");
			break;
		case DB_BAD_MAGIC:
            printf("\nThis file is not a valid password database or your password is incorrect\n");
			break;
		case DB_FILE_OPEN_ERROR:
            printf("\nAn error occured when opening the database\n");
			break;
		case DB_FILE_EXISTS:
            printf("\nA file with that name already exists\n");
			break;
		case DB_RECORD_EXISTS:
            printf("\nThis database already has a record with that name\n");
			break;
        case DB_RECORD_NOT_FOUND:
            printf("\nA record with that name could not be found\n");
            break;
		case DB_RECORD_LIMIT_REACHED:
            printf("\nThis database has reached its maximum capacity (1000 records)\n");
			break;
		case DB_NO_RECORDS:
            printf("\nThis database has no records in it\n");
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
	
	int pflag = -1;
	int comm_location = -1;
	char command[15];

    // Locate command name and possibly p flag
    /** Use of p flag currently disabled for potential security reasons **/

	int i;
	for(i = 0; i < argc; i++)
	{
		if(strcmp(argv[i], "-p") == 0 && pflag == -1)
		{
            //pflag = i;
		}
		else if(comm_location == -1)
		{
			int j;
			for(j = 0; j < num_comms; j++)
			{
				if(strcmp(argv[i], commands[j]) == 0)
				{
					comm_location = i;
					strcpy(command, commands[j]);
					break;
				}
			}
		}
	}
	
    // Check that command is valid

    if(argc > 4 || argc < 3)
    {
        printf("\nError: Invalid command\nType '<program> help' to get list of commands and proper usage\n");
        return 1;
    }

    if(comm_location == pflag + 1)
	{
        printf("\nError: Invalid command\nType '<program> help' to get list of commands and proper usage\n");
		return 1;
	}
	
	if(comm_location == -1 || comm_location == argc - 1)
	{
        printf("\nError: Invalid command\nType '<program> help' to get list of commands and proper usage\n");
		return 1;
	}

	if(pflag == argc - 1)
	{
        printf("\nError: no password given\nType '<program> help' to get list of commands and proper usage\n");
		return 1;
	}
	
    // P flag indicates password is given with command
    /** Use of p flag currently disabled for potential security reasons **/

	char password[MAX_PASS_LENGTH];
	if(pflag == -1)
	{
		memset(password, 0, MAX_PASS_LENGTH);
		printf("\nEnter this database's password\n$ ");
		fgets(password, MAX_PASS_LENGTH, stdin);
		password[strlen(password) - 1] = '\0';
	}
	else
	{
		if(strlen(argv[pflag + 1]) >= MAX_PASS_LENGTH)
		{
            printf("\nError: Database passwords must be 33 characters or less\n");
			return 1;
		}
		else
		{
			strcpy(password, argv[pflag + 1]);
		}
	}
	
	int error_code = 0;
	db_handle_t handle;
	
	if(strcmp(command, "create") == 0)
	{		
		if(error_code = create_pass_db(argv[comm_location + 1], password, &handle))
		{
			handle_errors(error_code);
			return 1;
		}
		else
		{
            printf("\nDatabase successfully created\n");
			close_handle(&handle);
			return 0;
		}
	}
	else if(strcmp(command, "get") == 0)
	{
        if(comm_location >= argc - 2)
		{
            printf("\nError: Invalid command\nType '<program> help' to get list of commands and proper usage\n");
			return 1;
		}
		else if(error_code = open_pass_db(argv[comm_location + 1], password, &handle))
		{
			handle_errors(error_code);
			return 1;
		}
		else
		{
			char *output = get_pass(argv[comm_location + 2], &handle);
			if(output)
			{
				printf("%s\n", output);
				memset(output, 0, sizeof(output));
				close_handle(&handle);
				return 0;
			}
			else
			{
                printf("\nA record with that name was not found\n");
				close_handle(&handle);
				return 1;
			}
		}
	}
	else if(strcmp(command, "add") == 0)
	{
        if(comm_location >= argc - 2)
		{
            printf("\nError: Invalid command\nType '<program> help' to get list of commands and proper usage\n");
			return 1;
		}
		else if(error_code = open_pass_db(argv[comm_location + 1], password, &handle))
		{
			handle_errors(error_code);
			return 1;
		}
		else
		{
			if(find_record(argv[comm_location + 2], &handle) != -1)
			{
                printf("\nA record with that name already exists\n");
				close_handle(&handle);
				return 1;
			}

            /** Need to check if input is a number **/

            int pass_size;
            printf("\nHow long would you like this password to be?\n");
			printf("(Maximum 10000 characters)\n$ ");
            scanf("%d", &pass_size);
            //scanf("%*[^\n]%1*[\n]");

            while(pass_size > 10000)
			{
				printf("\nPasswords can't be over 10000 characters long\n");
				printf("Please enter a smaller value\n$ ");
                scanf("%d", &pass_size);
			}
				
			if(error_code = create_db_record(argv[comm_location + 2], pass_size, &handle))
			{
				handle_errors(error_code);
				close_handle(&handle);
				return 1;
			}
			else
			{
                printf("\nPassword successfully added to database\n");
				close_handle(&handle);
				return 0;
			}
		}
	}
	else if(strcmp(command, "remove") == 0)
	{
        if(comm_location >= argc - 2)
		{
			printf("Error: Invalid command\nType '<program> help' to get list of commands and proper usage\n");
			return 1;
		}
		else if(error_code = open_pass_db(argv[comm_location + 1], password, &handle))
		{
			handle_errors(error_code);
			return 1;
		}
		else
		{
            if(error_code = delete_db_record(argv[comm_location + 2], &handle))
            {
                handle_errors(error_code);
                return 1;
            }
				
            printf("\nPassword successfully removed from database\n");
			close_handle(&handle);
			return 0;
		}
	}
	else if(strcmp(command, "list") == 0)
	{
		if(error_code = open_pass_db(argv[comm_location + 1], password, &handle))
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
    else if(strcmp(command, "info") == 0)
    {
        if(error_code = open_pass_db(argv[comm_location + 1], password, &handle))
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
	
	return 0;
}
