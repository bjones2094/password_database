#include "pass_safe.h"

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
			printf("\n-------- Enter the password you used to encrypt this database --------\n$ ");
			fgets(password, MAX_PASS_LENGTH, stdin);
			password[MAX_PASS_LENGTH - 1] = '\0';
			
			int error_code;
			db_handle_t *handle = malloc(sizeof(db_handle_t));
			if(error_code = open_pass_db(argv[2], password, handle))
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
				}
				return 1;
			}
			else
			{
				char *output = get_pass(argv[3], handle);
				if(output)
				{
					printf("%s\n", output);
				}
				else
				{
					printf("\nA record with that name was not found\n");
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
			printf("\n-------- Enter the password you used to encrypt this database with --------\n$ ");
			fgets(password, MAX_PASS_LENGTH, stdin);
			password[MAX_PASS_LENGTH - 1] = '\0';
			
			int error_code;
			db_handle_t *handle = malloc(sizeof(db_handle_t));
			if(error_code = create_pass_safe(argv[2], password, handle))
			{
				switch(error_code)
				{
					case DB_FILE_EXISTS:
						printf("\nA file with that name already exists\n");
						break;
					case DB_FILE_OPEN_ERROR:
						printf("\nAn error occured when creating the database\n");
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
			printf("\n-------- Enter the password you used to encrypt this database with --------\n$ ");
			fgets(password, MAX_PASS_LENGTH, stdin);
			password[MAX_PASS_LENGTH - 1] = '\0';
			
			int error_code;
			db_handle_t *handle = malloc(sizeof(db_handle_t));
			if(error_code = open_pass_db(argv[2], password, handle))
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
					printf("Passwords can't be over 10000 characters long\n");
					printf("Please enter a smaller value\n$ ");
					fgets(input, MAX_INT_INPUT_LENGTH, stdin);
					pass_size = atoi(input);
				}
				
				error_code = create_db_record(argv[3], pass_size, handle);
				switch(error_code)
				{
					case DB_RECORD_EXISTS:
						printf("\nThis database already has a record with that name\n");
						return 1;
						break;
					case DB_FILE_OPEN_ERROR:
						printf("\nAn error occured when writing to the database\n");
						return 1;
						break;
				}
				
				printf("\nPassword successfully added to database\n");
				return 0;
			}
		}
	}
	else
	{
		printf("Invalid arguments\n");
		return 1;
	}
	
	return 0;
}
