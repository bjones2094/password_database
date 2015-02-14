#ifndef PASS_SAFE_H
#define PASS_SAFE_H

#include <stdlib.h>
#include <time.h>
#include <gcrypt.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

// Input definitions
#define MAX_INPUT_LENGTH 1024
#define MAX_PASS_LENGTH 32
#define MAX_PASS_NAME_LENGTH 33
#define MAX_INT_INPUT_LENGTH 7

// Database definitions
#define KEY_SIZE 32
#define SALT_LENGTH 32
#define IV_LENGTH 16
#define AES_BLOCK_LENGTH 16
#define MAGIC_DB_CONSTANT 0xD00DBABE

/* --- Error code definitions --- */

// Opening database
#define DB_FILE_NOT_FOUND 1
#define DB_BAD_FILE_SIZE 2
#define DB_BAD_MAGIC 3
#define DB_FILE_OPEN_ERROR 4

// Editing database
#define DB_FILE_EXISTS 5
#define DB_RECORD_EXISTS 6
#define DB_RECORD_NOT_FOUND 7
#define DB_NO_RECORDS 8
#define DB_RECORD_LIMIT_REACHED 9

gcry_error_t error;

// Struct to hold data extracted from password headers

typedef struct pass_header
{
	char name[32];
	uint64_t size;
	uint64_t record_start;
} pass_header_t;

// Struct to hold current state of an opened database

typedef struct db_handle
{
	char *filename;
	uint32_t num_records;
	uint64_t last_edit;
	
	char *salt;
	char *iv;
	
	pass_header_t *pass_headers;
	char *pass_data;
	long pass_data_size;
	
	gcry_cipher_hd_t crypt_handle;
} db_handle_t;

void init_gcrypt();

char * generate_key(char *password, char *salt);
int generate_pass(unsigned char **pass_buff, int length);

int create_pass_db(char *filename, char *password, db_handle_t *handle);
int open_pass_db(char *infilename, char *password, db_handle_t *handle);

int create_db_record(char *name, int size, db_handle_t *handle);
int delete_db_record(char *name, db_handle_t *handle);

int write_handle(db_handle_t *handle);
void close_handle(db_handle_t *handle);

char * get_pass(char *name, db_handle_t *handle);
int find_record(char *name, db_handle_t *handle);
int list_records(db_handle_t *handle);

#endif
