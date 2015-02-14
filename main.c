#include "pass_safe.h"

void print_help()
{
	printf("\nUsage:\n");
	printf("    <programname> <command> <filename>\n");
	printf("    <programname> <command> <filename> <passwordname>\n\n");
	
	printf("Commands:\n");
	printf("    create | Create a new password database\n");
	printf("    add    | Add a new password to the database\n");
	printf("    remove | Remove a password from the database\n");
	printf("    get    | Get a password from the database\n");
	printf("    list   | List all passwords in the database\n");
	printf("    help   | Print help page\n\n");
	
	printf("Examples:\n");
	printf("    ./main create my_passwords\n");
	printf("    ./main list my_passwords\n");
	printf("    ./main add my_passwords email_password\n");
	printf("    ./main get my_passwords email_password\n\n");
}

int main(int argc, char **argv)
{
	init_gcrypt();
	
	if(argc > 1)
	{
		if(strcmp(argv[1], "get") == 0)
		{
			if(argc != 4)
			{
				printf("Invalid number of arguments\n");
				return 1;
			}
			
			char password[MAX_PASS_LENGTH];
			memset(password, 0, MAX_PASS_LENGTH);
			printf("\nEnter the password you used to encrypt this database\n$ ");
			fgets(password, MAX_PASS_LENGTH, stdin);
			password[MAX_PASS_LENGTH - 1] = '\0';
			
			int error_code;
			db_handle_t handle;
			if(error_code = open_pass_db(argv[2], password, &handle))
			{
				switch(error_code)
				{
					case DB_FILE_NOT_FOUND:
						printf("A file with that name could not be found\n");
						break;
					case DB_BAD_FILE_SIZE:
						printf("This file is not a valid password database\n");
						break;
					case DB_BAD_MAGIC:
						printf("This file is not a valid password database or your password is incorrect\n");
						break;
					case DB_FILE_OPEN_ERROR:
						printf("An error occured when opening the database\n");
						break;
				}
				return 1;
			}
			else
			{
				char *output = get_pass(argv[3], &handle);
				if(output)
				{
					printf("%s\n", output);
					memset(output, 0, sizeof(output));
				}
				else
				{
					printf("A record with that name was not found\n");
					return 1;
				}
			}
		}
		else if(strcmp(argv[1], "create") == 0)
		{
			if(argc != 3)
			{
				printf("Invalid number of arguments\n");
				return 1;
			}
			
			char password[MAX_PASS_LENGTH];
			memset(password, 0, MAX_PASS_LENGTH);
			printf("\nEnter the password you want to encrypt this database with\n$ ");
			fgets(password, MAX_PASS_LENGTH, stdin);
			password[MAX_PASS_LENGTH - 1] = '\0';
			
			int error_code;
			db_handle_t handle;
			if(error_code = create_pass_db(argv[2], password, &handle))
			{
				switch(error_code)
				{
					case DB_FILE_EXISTS:
						printf("A file with that name already exists\n");
						break;
					case DB_FILE_OPEN_ERROR:
						printf("An error occured when creating the database\n");
						break;
				}
				return 1;
			}
			else
			{
				printf("Database successfully created\n");
				return 0;
			}
		}
		else if(strcmp(argv[1], "add") == 0)
		{
			if(argc != 4)
			{
				printf("Invalid number of arguments\n");
				return 1;
			}
			
			char password[MAX_PASS_LENGTH];
			memset(password, 0, MAX_PASS_LENGTH);
			printf("\nEnter the password you used to encrypt this database\n$ ");
			fgets(password, MAX_PASS_LENGTH, stdin);
			password[MAX_PASS_LENGTH - 1] = '\0';
			
			int error_code;
			db_handle_t handle;
			if(error_code = open_pass_db(argv[2], password, &handle))
			{
				switch(error_code)
				{
					case DB_FILE_NOT_FOUND:
						printf("A file with that name could not be found\n");
						break;
					case DB_BAD_FILE_SIZE:
						printf("This file is not a valid password database\n");
						break;
					case DB_BAD_MAGIC:
						printf("This file is not a valid password database or your password is incorrect\n");
						break;
					case DB_FILE_OPEN_ERROR:
						printf("An error occured when opening the database\n");
						break;
				}
				return 1;
			}
			else
			{
				char input[MAX_INT_INPUT_LENGTH];
				printf("How long would you like this password to be?\n");
				printf("(Maximum 10000 characters)\n$ ");
				fgets(input, MAX_INT_INPUT_LENGTH, stdin);
				int pass_size = atoi(input);
			
				while(pass_size > 10000)
				{
					printf("\nPasswords can't be over 10000 characters long\n");
					printf("Please enter a smaller value\n$ ");
					fgets(input, MAX_INT_INPUT_LENGTH, stdin);
					pass_size = atoi(input);
				}
				
				error_code = create_db_record(argv[3], pass_size, &handle);
				switch(error_code)
				{
					case DB_RECORD_EXISTS:
						printf("This database already has a record with that name\n");
						return 1;
						break;
					case DB_FILE_OPEN_ERROR:
						printf("An error occured when writing to the database\n");
						return 1;
						break;
					case DB_RECORD_LIMIT_REACHED:
						printf("This database has reached its maximum capacity (1000 records)\n");
						return 1;
						break;
				}
				
				printf("Password successfully added to database\n");
				return 0;
			}
		}
		else if(strcmp(argv[1], "remove") == 0)
		{
			if(argc != 4)
			{
				printf("Invalid number of arguments\n");
				return 1;
			}
			
			char password[MAX_PASS_LENGTH];
			memset(password, 0, MAX_PASS_LENGTH);
			printf("\nEnter the password you used to encrypt this database\n$ ");
			fgets(password, MAX_PASS_LENGTH, stdin);
			password[MAX_PASS_LENGTH - 1] = '\0';
			
			int error_code;
			db_handle_t handle;
			if(error_code = open_pass_db(argv[2], password, &handle))
			{
				switch(error_code)
				{
					case DB_FILE_NOT_FOUND:
						printf("A file with that name could not be found\n");
						break;
					case DB_BAD_FILE_SIZE:
						printf("This file is not a valid password database\n");
						break;
					case DB_BAD_MAGIC:
						printf("This file is not a valid password database or your password is incorrect\n");
						break;
					case DB_FILE_OPEN_ERROR:
						printf("An error occured when opening the database\n");
						break;
				}
				return 1;
			}
			else
			{
				error_code = delete_db_record(argv[3], &handle);
				switch(error_code)
				{
					case DB_RECORD_NOT_FOUND:
						printf("A record with that name could not be found\n");
						return 1;
						break;
					case DB_FILE_OPEN_ERROR:
						printf("An error occured when writing to the database\n");
						return 1;
						break;
				}
				
				printf("Password successfully removed from database\n");
				close_handle(&handle);
				return 0;
			}
		}
		else if(strcmp(argv[1], "list") == 0)
		{
			if(argc != 3)
			{
				printf("Invalid number of arguments\n");
				return 1;
			}
			
			char password[MAX_PASS_LENGTH];
			memset(password, 0, MAX_PASS_LENGTH);
			printf("\nEnter the password you used to encrypt this database\n$ ");
			fgets(password, MAX_PASS_LENGTH, stdin);
			password[MAX_PASS_LENGTH - 1] = '\0';
			
			int error_code;
			db_handle_t handle;
			if(error_code = open_pass_db(argv[2], password, &handle))
			{
				switch(error_code)
				{
					case DB_FILE_NOT_FOUND:
						printf("A file with that name could not be found\n");
						break;
					case DB_BAD_FILE_SIZE:
						printf("This file is not a valid password database\n");
						break;
					case DB_BAD_MAGIC:
						printf("This file is not a valid password database or your password is incorrect\n");
						break;
					case DB_FILE_OPEN_ERROR:
						printf("An error occured when opening the database\n");
						break;
				}
				return 1;
			}
			else
			{
				if(list_records(&handle))
				{
					printf("This database has no records in it\n");
					return 1;
				}
				close_handle(&handle);
				return 0;
			}
		}
		else if(strcmp(argv[1], "help") == 0)
		{
			print_help();
		}
		else
		{
			printf("Command not found : use 'help' command to get list of commands\n");
			return 1;
		}
	}
	else
	{
		printf("Invalid arguments\n");
		return 1;
	}
	
	return 0;
}
