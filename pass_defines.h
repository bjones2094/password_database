#ifndef PASS_DEFINES_H
#define PASS_DEFINES_H

// Tuning parameters for scrypt key gen
#define KEY_GEN_N 262144
#define KEY_GEN_P 1

// Input definitions
#define MAX_INPUT_LENGTH 1024
#define MAX_PASS_LENGTH 33
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

#endif
