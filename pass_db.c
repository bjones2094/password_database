#include "pass_db.h"
#include "pass_defines.h"
#include <stdlib.h>
#include <time.h>
#include <gcrypt.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

// Initialize libgcrypt library
void init_gcrypt()
{
    if(!gcry_check_version (GCRYPT_VERSION))
    {
        fputs("libgcrypt version mismatch\n", stderr);
        exit(EXIT_FAILURE);
    }
    
    gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
    gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
}

// Generate a random password length bytes long
// Returns length of actual password block
int generate_pass(unsigned char **pass_buff, int length)
{
    int password_block_length = (length + 1) % AES_BLOCK_LENGTH ? length + 1 + AES_BLOCK_LENGTH - ((length + 1) % AES_BLOCK_LENGTH) : length + 1;
    *pass_buff = malloc(password_block_length);
    gcry_randomize(*pass_buff, password_block_length, GCRY_STRONG_RANDOM);
            
    // Make password characters readable 
    int i;
    for(i = 0; i < length; i++)
    {
        (*pass_buff)[i] = (*pass_buff)[i] % ('~' - ' ') + ' ';
    }
    
    // Pad end of password with null terminators
    for(i = length; i < password_block_length; i++)
    {
        (*pass_buff)[i] = '\0';
    }
    
    return password_block_length;
}

// Create a new password database file and initialize database handle
int create_pass_db(char *filename, char *password, db_handle_t *handle)
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

    // Derive encryption key using scrypt algorithm
    char *key = malloc(KEY_SIZE);
    gcry_kdf_derive(password, strlen(password), GCRY_KDF_SCRYPT, KEY_GEN_N, salt, SALT_LENGTH, KEY_GEN_P, KEY_SIZE, key);
        
    // Initialize cipher handle for encryption/decryption
    gcry_cipher_open(&(handle->crypt_handle), GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
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
        
        // Derive encryption key using scrypt algorithm
        char *key = malloc(KEY_SIZE);
        gcry_kdf_derive(password, strlen(password), GCRY_KDF_SCRYPT, KEY_GEN_N, handle->salt, SALT_LENGTH, KEY_GEN_P, KEY_SIZE, key);
        
        // Initialize cipher handle for encryption/decryption
        gcry_cipher_open(&(handle->crypt_handle), GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
        gcry_cipher_setkey(handle->crypt_handle, key, KEY_SIZE);
        gcry_cipher_setiv(handle->crypt_handle, handle->iv, IV_LENGTH);
        
        memset(key, 0, KEY_SIZE);
        free(key);
        
        // Read and decrypt database header from next 16 bytes
        char db_header[DB_HEADER_LENGTH];
        fread(db_header, DB_HEADER_LENGTH, 1, infile);
        
        error = gcry_cipher_decrypt(handle->crypt_handle, db_header, DB_HEADER_LENGTH, NULL, 0);
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
        
        if(handle->num_records > 0)
        {
            // Read and decrypt password header data into pass_header structs

            handle->pass_headers = malloc(sizeof(pass_header_t) * handle->num_records);
            char header_block[PASS_HEADER_LENGTH];
            
            int i;
            for(i = 0; i < handle->num_records; i++)
            {
                fread(header_block, PASS_HEADER_LENGTH, 1, infile);
                
                error = gcry_cipher_decrypt(handle->crypt_handle, header_block, PASS_HEADER_LENGTH, NULL, 0);
                if(error)
                {
                    printf("%s\n", gcry_strerror(error));
                    exit(EXIT_FAILURE);
                }
                
                pass_header_t *p_head = &handle->pass_headers[i];

                int pass_size_offset = sizeof(p_head->name);
                int create_time_offset = pass_size_offset + sizeof(p_head->pass_size);
                int record_size_offset = create_time_offset + sizeof(p_head->create_time);
                int record_start_offset = record_size_offset + sizeof(p_head->record_size);

                memcpy(p_head->name, header_block, sizeof(p_head->name));
                memcpy(&(p_head->pass_size), header_block + pass_size_offset, sizeof(p_head->pass_size));
                memcpy(&(p_head->create_time), header_block + create_time_offset, sizeof(p_head->create_time));
                memcpy(&(p_head->record_size), header_block + record_size_offset, sizeof(p_head->record_size));
                memcpy(&(p_head->record_start), header_block + record_start_offset, sizeof(p_head->record_start));
            }
            
            // Read encrypted password data into handle
            handle->pass_data_size = file_size - ftell(infile);
            handle->pass_data = malloc(handle->pass_data_size);
            fread(handle->pass_data, handle->pass_data_size, 1, infile);
            
            fclose(infile);
        }
        else
        {
            handle->pass_headers = NULL;
            handle->pass_data = NULL;
            handle->pass_data_size = 0;
        }
        return 0;
    }
}

// Add a new password record to an exisiting database
int create_db_record(char *name, int pass_size, db_handle_t *handle)
{
    if(find_record(name, handle) != -1)
    {
        return DB_RECORD_EXISTS;
    }
    else if(handle->num_records == 1000)    // Each db can only hold 1000 records
    {
        return DB_RECORD_LIMIT_REACHED;
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
    
    // Start of new record is at end of current password block
    new_pass_header.record_start = handle->pass_data_size;

    new_pass_header.pass_size = pass_size;
    new_pass_header.create_time = time(NULL);

    // Generate random password
    unsigned char *password_block;
    int password_block_length = generate_pass(&password_block, pass_size);
    
    // Encrypt password block in place

    // Re-initialize iv so password encryption is consistent
    gcry_cipher_setiv(handle->crypt_handle, handle->iv, IV_LENGTH);
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
    free(password_block);
    
    // Add new password header to handle headers
    new_pass_header.record_size = password_block_length;
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

// Remove a password record from an existing database
int delete_db_record(char *name, db_handle_t *handle)
{
    int location;
    if((location = find_record(name, handle)) == -1)
    {
        return DB_RECORD_NOT_FOUND;
    }
    
    pass_header_t header = handle->pass_headers[location];
    int record_end = header.record_start + header.record_size;
    
    // Remove password data from handle
    char *new_pass_data = malloc(handle->pass_data_size - header.record_size);
    memcpy(new_pass_data, handle->pass_data, header.record_start);
    memcpy(new_pass_data, handle->pass_data + record_end, handle->pass_data_size - record_end);
    
    free(handle->pass_data);
    handle->pass_data = new_pass_data;
    
    // Remove appropriate password header from handle
    pass_header_t *new_headers = malloc(sizeof(pass_header_t) * (handle->num_records - 1));
    int i;
    for(i = 0; i < location; i++)
    {
        new_headers[i] = handle->pass_headers[i];
    }
    for(i = location; i < handle->num_records - 1; i++)
    {
        new_headers[i] = handle->pass_headers[i + 1];
        new_headers[i].record_start -= header.record_size;    // Fix header record starts
    }
    
    free(handle->pass_headers);
    handle->pass_headers = new_headers;
    handle->num_records--;
    
    return write_handle(handle);
}

// Write state of password database provided by db_handle to appropriate database file
int write_handle(db_handle_t *handle)
{
    FILE *outfile = fopen(handle->filename, "wb");
    
    if(!outfile)
    {
        return DB_FILE_OPEN_ERROR;
    }

    // Re-initialize iv so header encryption is consistent
    gcry_cipher_setiv(handle->crypt_handle, handle->iv, IV_LENGTH);
    
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
    char pass_header[PASS_HEADER_LENGTH];
    for(i = 0; i < handle->num_records; i++)
    {
        pass_header_t p_head = handle->pass_headers[i];
        
        int pass_size_offset = sizeof(p_head.name);
        int create_time_offset = pass_size_offset + sizeof(p_head.pass_size);
        int record_size_offset = create_time_offset + sizeof(p_head.create_time);
        int record_start_offset = record_size_offset + sizeof(p_head.record_size);

        memcpy(pass_header, p_head.name, sizeof(p_head.name));
        memcpy(pass_header + pass_size_offset, &(p_head.pass_size), sizeof(p_head.pass_size));
        memcpy(pass_header + create_time_offset, &(p_head.create_time), sizeof(p_head.create_time));
        memcpy(pass_header + record_size_offset, &(p_head.record_size), sizeof(p_head.record_size));
        memcpy(pass_header + record_start_offset, &(p_head.record_start), sizeof(p_head.record_start));
        
        error = gcry_cipher_encrypt(handle->crypt_handle, pass_header, PASS_HEADER_LENGTH, NULL, 0);
        if(error)
        {
            printf("%s\n", gcry_strerror(error));
            exit(EXIT_FAILURE);
        }
        fwrite(pass_header, PASS_HEADER_LENGTH, 1, outfile);
    }
    
    // Write encrypted password data to file
    fwrite(handle->pass_data, 1, handle->pass_data_size, outfile);
    fclose(outfile);
    
    return 0;
}

// Clean up memory from db handle
void close_handle(db_handle_t *handle)
{
    // Zero out decrypted password header data
    memset(handle->pass_headers, 0, sizeof(pass_header_t) * handle->num_records);
    
    free(handle->filename);
    free(handle->salt);
    free(handle->iv);
    free(handle->pass_headers);
    free(handle->pass_data);
    gcry_cipher_close(handle->crypt_handle);
}

// Retrieve a password from an opened database
char * get_pass(char *name, db_handle_t *handle)
{
    pass_header_t header;
    
    // Check if record exists

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

    char *pass_buff = malloc(header.record_size);
    memcpy(pass_buff, handle->pass_data + header.record_start, header.record_size);
    
    // Decrypt password record

    // Re-initialize iv so password encryption is consistent
    gcry_cipher_setiv(handle->crypt_handle, handle->iv, IV_LENGTH);
    error = gcry_cipher_decrypt(handle->crypt_handle, pass_buff, header.record_size, NULL, 0);
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
        if(strcmp(name, handle->pass_headers[i].name) == 0)
        {
            return i;
        }
    }
    return -1;
}

// List all password records within an opened database
int list_records(db_handle_t *handle)
{
    if(handle->num_records == 0)
    {
        return DB_NO_RECORDS;
    }
    
    printf("\n");
    int i;
    for(i = 0; i < handle->num_records; i++)
    {
        char *create_time = ctime((time_t *) &(handle->pass_headers[i].create_time));

        printf("Name: %s | ", handle->pass_headers[i].name);
        printf("%lu characters long\n", handle->pass_headers[i].pass_size);
        printf("Created: %s\n", create_time);
    }
    printf("\n");
    return 0;
}

// Print information about database contents
void print_db_info(db_handle_t *handle)
{
    char *last_edit = ctime((time_t *) &(handle->last_edit));

    printf("\nFile Name: %s\n", handle->filename);
    printf("Number of Records: %u\n", handle->num_records);
    printf("Last Edited: %s\n", last_edit);
}
