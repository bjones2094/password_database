#include "pass_safe.h"

// Initialize libgcrypt library
void init_gcrypt()
{
	if(!gcry_check_version (GCRYPT_VERSION))
	{
		fputs("!!! libgcrypt version mismatch !!!\n", stderr);
		exit(EXIT_FAILURE);
	}
	
	gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
	gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
}

// Generate an AES256 key from a password
char * generate_key(char *password, char *salt)
{
	char *digest = malloc(KEY_SIZE);
	gcry_md_hash_buffer(GCRY_MD_SHA256, digest, password, strlen(password));
	
	int i;
	for(i = 0; i < KEY_SIZE; i++)
	{
		digest[i] ^= salt[i];
	}
	
	return digest;
}

// Open an existing password database
int open_pass_db(char *infilename, char *password, db_handle_t *handle)
{
	if(access(infilename, F_OK) == -1)
	{
		return DB_FILE_NOT_FOUND;
	}
	else
	{	
		FILE *infile = fopen(infilename, "rb");
		if(!infile)
		{
			return DB_FILE_OPEN_ERROR;
		}
		
		fseek(infile, 0, SEEK_END);
		long file_size = ftell(infile);
		rewind(infile);
		
		// Files must be of a size divisible by AES cipher block length
		if(file_size % AES_BLOCK_LENGTH)
		{
			return DB_BAD_FILE_SIZE;
		}
		
		// Salt and IV are stored at beginning of file (unencrypted)
		handle->salt = malloc(SALT_LENGTH);
		fread(handle->salt, sizeof(char), SALT_LENGTH, infile);
		
		handle->iv = malloc(IV_LENGTH);
		fread(handle->iv, sizeof(char), IV_LENGTH, infile);
		
		char *key = generate_key(password, handle->salt);
		
		// Initialize cipher handle for encryption/decryption
		gcry_cipher_open(&(handle->crypt_handle), GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, 0);
		gcry_cipher_setkey(handle->crypt_handle, key, KEY_SIZE);
		gcry_cipher_setiv(handle->crypt_handle, handle->iv, IV_LENGTH);
		
		// Read and decrypt database header from next 16 bytes
		char db_header[AES_BLOCK_LENGTH];
		fread(db_header, AES_BLOCK_LENGTH, 1, infile);
		
		error = gcry_cipher_decrypt(handle->crypt_handle, db_header, AES_BLOCK_LENGTH, NULL, 0);
		if(error)
		{
			printf("%s\n", gcry_strerror(error));
			exit(EXIT_FAILURE);
		}
		
		// Check for magic constant to verify database
		uint32_t magic_check;
		memcpy(&magic_check, db_header, sizeof(uint32_t));
		if(magic_check != MAGIC_DB_CONSTANT)
		{
			return DB_BAD_MAGIC;
		}
		
		// Load header data into handle struct
		memcpy(&(handle->num_records), db_header + sizeof(uint32_t), sizeof(uint32_t));
		memcpy(&(handle->last_edit), db_header + sizeof(uint32_t) * 2 , sizeof(uint64_t));
		
		handle->filename = malloc(strlen(infilename) + 1);
		strcpy(handle->filename, infilename);
		handle->last_edit = time(NULL);
		
		
		if(handle->num_records > 0)
		{
			// Read and decrypt password header data into pass_header structs
			handle->pass_headers = malloc(sizeof(pass_header_t) * handle->num_records);
			char header_block[AES_BLOCK_LENGTH * 3];
			
			int i;
			for(i = 0; i < handle->num_records; i++)
			{
				fread(header_block, AES_BLOCK_LENGTH, 3, infile);
				
				error = gcry_cipher_decrypt(handle->crypt_handle, header_block, AES_BLOCK_LENGTH * 3, NULL, 0);
				if(error)
				{
					printf("%s\n", gcry_strerror(error));
					exit(EXIT_FAILURE);
				}
				
				pass_header_t *p_head = &handle->pass_headers[i];
				memcpy(p_head->name, header_block, sizeof(p_head->name));
				memcpy(&(p_head->size), header_block + sizeof(p_head->name), sizeof(p_head->size));
				memcpy(&(p_head->record_start), header_block + sizeof(p_head->name) + sizeof(p_head->size), sizeof(p_head->record_start));
			}
			
			// Read encrypted password data into handle
			handle->pass_data_size = file_size - ftell(infile);
			handle->pass_data = malloc(handle->pass_data_size);
			fread(handle->pass_data, handle->pass_data_size, 1, infile);
			
			fclose(infile);
		}
		else
		{
			handle->pass_data = NULL;
			handle->pass_data_size = 0;
		}
		return 0;
	}
}

// Write state of password database provided by db_handle to appropriate database file
int write_handle(db_handle_t *handle)
{
	FILE *outfile = fopen(handle->filename, "wb");
	
	if(!outfile)
	{
		return DB_FILE_OPEN_ERROR;
	}
	
	// Salt and IV are stored at beginning of file
	fwrite(handle->salt, 1, SALT_LENGTH, outfile);
	fwrite(handle->iv, 1, IV_LENGTH, outfile);
	
	handle->last_edit = time(NULL);
	
	// Write encrypted database header to file
	char db_header[AES_BLOCK_LENGTH];
	uint32_t magic = MAGIC_DB_CONSTANT;
	memcpy(db_header, &magic, sizeof(uint32_t));
	memcpy(db_header + sizeof(uint32_t), &(handle->num_records), sizeof(handle->num_records));
	memcpy(db_header + sizeof(uint32_t) + sizeof(handle->num_records), &(handle->last_edit), sizeof(handle->last_edit));
	
	error = gcry_cipher_encrypt(handle->crypt_handle, db_header, AES_BLOCK_LENGTH, NULL, 0);
	if(error)
	{
		printf("%s\n", gcry_strerror(error));
		exit(EXIT_FAILURE);
	}
	fwrite(db_header, AES_BLOCK_LENGTH, 1, outfile);
	
	// Write encrypted password headers to file
	int i;
	char pass_header[AES_BLOCK_LENGTH * 3];
	for(i = 0; i < handle->num_records; i++)
	{
		pass_header_t p_head = handle->pass_headers[i];
		
		memcpy(pass_header, p_head.name, sizeof(p_head.name));
		memcpy(pass_header + sizeof(p_head.name), &(p_head.size), sizeof(p_head.size));
		memcpy(pass_header + sizeof(p_head.name) + sizeof(p_head.size), &(p_head.record_start), sizeof(p_head.record_start));
		
		error = gcry_cipher_encrypt(handle->crypt_handle, pass_header, AES_BLOCK_LENGTH * 3, NULL, 0);
		if(error)
		{
			printf("%s\n", gcry_strerror(error));
			exit(EXIT_FAILURE);
		}
		fwrite(pass_header, AES_BLOCK_LENGTH, 3, outfile);
	}
	
	// Write encrypted password data to file
	fwrite(handle->pass_data, 1, handle->pass_data_size, outfile);
	fclose(outfile);
	
	return 0;
}

// Create a new password database file and initialize database handle
int create_pass_safe(char *filename, char *password, db_handle_t *handle)
{
	if(access(filename, F_OK) != -1)
	{
		return DB_FILE_EXISTS;
	}
	
	// Generate random salt for key generation
	char salt[SALT_LENGTH];
	gcry_randomize(salt, SALT_LENGTH, GCRY_STRONG_RANDOM);
		
	// Generate random initialization vector for encrypting
	char iv[IV_LENGTH];
	gcry_randomize(iv, IV_LENGTH, GCRY_STRONG_RANDOM);
		
	char *key = generate_key(password, salt);
		
	// Initialize cipher handle for encryption/decryption
	gcry_cipher_open(&(handle->crypt_handle), GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, 0);
	gcry_cipher_setkey(handle->crypt_handle, key, KEY_SIZE);
	gcry_cipher_setiv(handle->crypt_handle, iv, IV_LENGTH);
		
	// Initialize db header struct
	handle->filename = malloc(strlen(filename) + 1);
	strcpy(handle->filename, filename);
		
	handle->num_records = 0;
	handle->last_edit = time(NULL);
		
	handle->salt = malloc(SALT_LENGTH);
	memcpy(handle->salt, salt, SALT_LENGTH);
		
	handle->iv = malloc(IV_LENGTH);
	memcpy(handle->iv, iv, IV_LENGTH);
		
	handle->pass_headers = NULL;
	handle->pass_data = NULL;
	handle->pass_data_size = 0;
		
	// Write handle to file
	return write_handle(handle);
}

// Add a new password record to an exisiting database
int create_db_record(char *name, int pass_size, db_handle_t *handle)
{
	if(find_record(name, handle))
	{
		return DB_RECORD_EXISTS;
	}
	
	// Create new password header
	pass_header_t new_pass_header;
	strcpy(new_pass_header.name, name);
	
	// Pad end of name with null terminators
	int i;
	for(i = strlen(new_pass_header.name); i < sizeof(new_pass_header.name); i++)
	{
		new_pass_header.name[i] = '\0';
	}
	
	new_pass_header.record_start = handle->pass_data_size;
	
	// Generate new random password of pass_size bytes
	unsigned char new_password[pass_size];
	gcry_randomize(new_password, pass_size, GCRY_STRONG_RANDOM);
			
	// Make every character readable 
	for(i = 0; i < pass_size; i++)
	{
		new_password[i] = new_password[i] % ('~' - ' ') + ' ';
	}
	
	// Fit new password into a block of a size divisible by AES block size
	long password_block_length = (pass_size + 1) % AES_BLOCK_LENGTH ? pass_size + 1 + AES_BLOCK_LENGTH - ((pass_size + 1) % AES_BLOCK_LENGTH) : pass_size + 1;
	char password_block[password_block_length];
	memcpy(password_block, new_password, pass_size);
	
	// Pad end of password with null terminators
	for(i = pass_size; i < password_block_length; i++)
	{
		password_block[i] = '\0';
	}
	
	// Encrypt password block in place
	error = gcry_cipher_encrypt(handle->crypt_handle, password_block, password_block_length, NULL, 0);
	if(error)
	{
		printf("%s\n", gcry_strerror(error));
		exit(EXIT_FAILURE);
	}
	
	// Add new password data to current handle data
	if(handle->num_records == 0)
	{
		handle->pass_data = malloc(password_block_length);
		memcpy(handle->pass_data, password_block, password_block_length);
	}
	else
	{
		char *new_pass_data = malloc(handle->pass_data_size + password_block_length);
		memcpy(new_pass_data, handle->pass_data, handle->pass_data_size);
		memcpy(new_pass_data + handle->pass_data_size, password_block, password_block_length);
		
		free(handle->pass_data);
		handle->pass_data = new_pass_data;
	}
	handle->pass_data_size += password_block_length;
	
	// Add new password header to handle headers
	new_pass_header.size = password_block_length;
	if(handle->num_records == 0)
	{
		handle->pass_headers = malloc(sizeof(pass_header_t));
	}
	else
	{
		pass_header_t *new_headers = malloc(sizeof(pass_header_t) * (handle->num_records + 1));
		memcpy(new_headers, handle->pass_headers, sizeof(pass_header_t) * handle->num_records);
	
		free(handle->pass_headers);
		handle->pass_headers = new_headers;
	}
	handle->num_records++;
	handle->pass_headers[handle->num_records - 1] = new_pass_header;
	
	return write_handle(handle);
}

// Retrieve a password from an opened database
char * get_pass(char *name, db_handle_t *handle)
{
	pass_header_t header;
	
	int isfound = 0;
	int i;
	for(i = 0; i < handle->num_records; i++)
	{
		if(!strcmp(name, handle->pass_headers[i].name))
		{
			header = handle->pass_headers[i];
			isfound = 1;
			break;
		}
	}
	if(!isfound)
	{
		return NULL;
	}
	
	char *pass_buff = malloc(header.size);
	memcpy(pass_buff, handle->pass_data + header.record_start, header.size);
	
	error = gcry_cipher_decrypt(handle->crypt_handle, pass_buff, header.size, NULL, 0);
	if(error)
	{
		printf("%s\n", gcry_strerror(error));
		exit(EXIT_FAILURE);
	}
	
	return pass_buff;
}

// Determine if a record with name 'name' is in the opened database
int find_record(char *name, db_handle_t *handle)
{
	int i;
	for(i = 0; i < handle->num_records; i++)
	{
		if(!strcmp(name, handle->pass_headers[i].name))
		{
			return 1;
		}
	}
	return 0;
}

// List all password records within an opened database
int list_records(db_handle_t *handle)
{
	if(handle->num_records == 0)
	{
		return DB_NO_RECORDS;
	}
	
	int i;
	for(i = 0; i < handle->num_records; i++)
	{
		printf("Name: %s, ", handle->pass_headers[i].name);
		printf("Size: %s\n", handle->pass_headers[i].size);
	}
}
