#ifndef PASS_SAFE_H
#define PASS_SAFE_H

#include <gcrypt.h>
#include <stdint.h>

// Global variable for error codes

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
