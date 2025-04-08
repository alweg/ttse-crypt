#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

void encrypt(const char*, const char*, uint32_t);
void decrypt(const char*, const char*, uint32_t);

void encrypt_begin(FILE*, FILE*);
void decrypt_begin(FILE*, FILE*);

void write_header_secret(FILE*, uint8_t);
void write_header_checksum(FILE*, uint32_t);

uint8_t read_header_secret(FILE*);
uint32_t read_header_checksum(FILE*);

void write_encrypted(FILE*, int8_t, uint8_t*, uint8_t*);
void write_decrypted(FILE*, int8_t);

int32_t read_encrypted(FILE*, uint8_t*, uint8_t*);
int32_t read_decrypted(FILE*, uint32_t*);

char* key_stream_create();
uint8_t reverse_bits(uint8_t);

void create_general(const char*);
void create_general000(const char*, const char*);
