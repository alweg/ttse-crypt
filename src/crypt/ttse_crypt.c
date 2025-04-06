#pragma warning(disable : 4996)

#include "crypt/ttse_crypt.h"

void encrypt(const char* input_filepath, const char* output_filepath, uint32_t mode)
{
    FILE* fInput;
    FILE* fOutput;

    if (mode == 1) { }
    if (mode == 2)
    {
        fInput = fopen(input_filepath, "rb");
        if (!fInput)
        {
            printf("Cannot open '%s'.\n", input_filepath);
            return;
        }

        fOutput = fopen(output_filepath, "wb");
        if (!fOutput)
        {
            printf("Cannot open '%s'.\n", output_filepath);
            fclose(fInput);
            return;
        }

        printf("Encrypting: '%s'.\n", input_filepath);
        encrypt_begin(fInput, fOutput);
        printf("Output saved to: '%s'.\n", output_filepath);

        fclose(fInput);
        fclose(fOutput);
    }
}

void decrypt(const char* input_filepath, const char* output_filepath, uint32_t mode)
{
    FILE* fInput;
    FILE* fOutput;

    if (mode == 1) { }
    if (mode == 2)
    {
        fInput = fopen(input_filepath, "rb");
        if (!fInput)
        {
            printf("Cannot open '%s'.\n", input_filepath);
            return;
        }

        fOutput = fopen(output_filepath, "wb");
        if (!fOutput)
        {
            printf("Cannot open '%s'.\n", output_filepath);
            fclose(fInput);
            return;
        }

        printf("Decrypting: '%s'.\n", input_filepath);
        decrypt_begin(fInput, fOutput);
        printf("Output saved to: '%s'.\n", output_filepath);

        fclose(fInput);
        fclose(fOutput);
    }
}


void encrypt_begin(FILE* fInput, FILE* fOutput)
{
    // creates a 2056 byte stream where the last 8 bytes is used for a buffer
    char* key_stream = key_stream_create();

    // 8 byte buffer to process the read bytes
    char* key_buffer = key_stream + 2048;

    uint8_t rolling_key_1 = 87;
    uint8_t rolling_key_2 = 0;
    uint32_t total_bytes_read = 0;

    // writing 5 dummy bytes that get overwritten later
    write_header_secret(fOutput, 0u);
    write_header_checksum(fOutput, 0u);

    while(1)
    {
        uint8_t remaining_bytes = 8;

        for (uint8_t i = 0; i < 8; i++)
        {
            int32_t read_char = read_decrypted(fInput, &total_bytes_read);
            if (read_char == -1)
            {
                remaining_bytes = i;
                break;
            }

            key_buffer[i] = read_char;
        }

        uint32_t key_stream_offset = 0;
        int8_t previous_matches = -1;
        int32_t match_position = 0;

        for (uint32_t i = 0; i < 256; i++)
        {
            int8_t current_matches = 0;

            if (remaining_bytes > 0)
            {
                for (int j = 0; j < remaining_bytes; j++)
                {
                    if (key_buffer[j] == key_stream[key_stream_offset])
                        current_matches++;

                    key_stream_offset++;
                }
            }

            if (current_matches > previous_matches)
            {
                previous_matches = current_matches;
                match_position = i;

                if (current_matches == remaining_bytes)
                    break;
            }

            key_stream_offset += 8 - (int8_t)remaining_bytes;
        }

        write_encrypted(fOutput, (int8_t)match_position, &rolling_key_1, &rolling_key_2);

        uint8_t match_mask = 0;
        for (uint8_t i = 0, j = 1; i < 8; i++, j *= 2)
        {
            if (i >= remaining_bytes)
                break;

            if (key_buffer[i] != key_stream[8 * match_position + i])
                match_mask += j;
        }

        write_encrypted(fOutput, (int8_t)match_mask, &rolling_key_1, &rolling_key_2);

        for (uint8_t i = 0; i < 8; i++)
        {
            if (match_mask % 2 == 1)
                write_encrypted(fOutput, key_buffer[i], &rolling_key_1, &rolling_key_2);

            match_mask /= 2;
        }

        if (remaining_bytes >= 8)
        {
            for (uint8_t i = 0; i < 8; i++)
                key_stream[8 * match_position + i] = key_buffer[i];
        }
        else
        {
            write_encrypted(fOutput, remaining_bytes, &rolling_key_1, &rolling_key_2);
            break;
        }
    }

    // modifying the 5 dummy bytes
    write_header_secret(fOutput, rolling_key_2);
    write_header_checksum(fOutput, total_bytes_read);

    free(key_stream);
}

void decrypt_begin(FILE* fInput, FILE* fOutput)
{
    // creates a 2056 byte stream where the last 8 bytes is used for a buffer
    char* key_stream = key_stream_create();

    // 8 byte buffer to process the read bytes
    char* key_buffer = key_stream + 2048;

    uint8_t rolling_key_1 = 87;
    uint8_t rolling_key_2 = read_header_secret(fInput);
    
    // The 'header_checksum' is not really used in the decryption algorithm
    // Just skipping checksum instead
    // uint32_t header_checksum = read_header_secret(fInput);
    fseek(fInput, 4, 1); 

    uint32_t read_char_1 = 0;
    uint32_t read_char_2 = 0;

    read_char_1 = read_encrypted(fInput, &rolling_key_1, &rolling_key_2);
    if (read_char_1 != -1)
        read_char_2 = read_encrypted(fInput, &rolling_key_1, &rolling_key_2);

    while (1)
    {
        for (uint8_t j = 0; j < 8; j++)
        {
            if (read_char_2 % 2 == 1)
                key_stream[8 * read_char_1 + j] = read_encrypted(fInput, &rolling_key_1, &rolling_key_2);

            key_buffer[j] = key_stream[8 * read_char_1 + j];
            read_char_2 /= 2;
        }

        read_char_1 = read_encrypted(fInput, &rolling_key_1, &rolling_key_2);
        if (read_char_1 == -1)
        {
            for (uint8_t i = 0; i < 8; i++)
                write_decrypted(fOutput, key_buffer[i]);

            break;
        }

        read_char_2 = read_encrypted(fInput, &rolling_key_1, &rolling_key_2);
        if (read_char_2 == -1)
        {
            for (uint8_t i = 0; i < read_char_1; i++)
                write_decrypted(fOutput, key_buffer[i]);

            break;
        }

        for (uint8_t i = 0; i < 8; i++)
            write_decrypted(fOutput, key_buffer[i]);
    }

    free(key_stream);
}


void write_header_secret(FILE* fOutput, uint8_t key)
{
    fseek(fOutput, 0, 0);
    key ^= 0x53u;
    fwrite(&key, 1u, 1u, fOutput);
}

void write_header_checksum(FILE* fOutput, uint32_t key)
{
    key ^= 0x54555657u;
    fwrite(&key, 4u, 1u, fOutput);
}


char read_header_secret(FILE* fInput)
{
    char c;
    fread(&c, 1, 1, fInput);
    return (char)c ^ 0x53;
}

uint32_t read_header_checksum(FILE* fInput)
{
    uint32_t result;
    fread(&result, 4u, 1u, fInput);
    return (uint32_t)result ^ 0x54555657;
}


void write_encrypted(FILE* fOutput, int8_t input_char, uint8_t* rolling_key_1, uint8_t* rolling_key_2)
{
    uint8_t i = reverse_bits((*rolling_key_1)++);
    *rolling_key_2 += input_char;

    uint8_t encrypted_char = input_char ^ i ^ 0xB9;
    putc(encrypted_char, fOutput);

    //printf("Write at offset: %ld -> 0x%02x\n", ftell(fOutput) - 1, encrypted_char);
}

void write_decrypted(FILE* fOutput, int8_t input_char)
{
    // In the original function a flag is set if the 'header_checksum' gets 
    // below zero and breaks out the decryption algorithm.
    // But the 'header_checksum' never gets below zero, so it's useless.

    // if (--(*header_checksum) < 0)
        // some_flag = 1;

    putc(input_char, fOutput);
    // printf("Write at offset: %ld -> 0x%02x\n", ftell(fOutput) - 1, input_char);
}


int32_t read_encrypted(FILE* fInput, uint8_t* rolling_key_1, uint8_t* rolling_key_2)
{
    int32_t result = getc(fInput);
    if (result != -1)
    {
        result ^= reverse_bits((*rolling_key_1)++) ^ 0xB9;
        *rolling_key_2 -= result;
    }

    // printf("Read at offset: %ld -> 0x%02x\n", ftell(fInput) - 5, result);
    return result;
}

int32_t read_decrypted(FILE* fInput, uint32_t* total_bytes_read)
{
    int32_t result = fgetc(fInput);
    if (result != -1)
        (*total_bytes_read)++;

    //printf("Read at offset: %ld -> 0x%02x\n", ftell(fInput) - 1, result);
    return result;
}


char* key_stream_create()
{
    char* key_stream = (char*)malloc(2056 * sizeof(int8_t));

    if (key_stream == (void*)0)
        return (void*)0;

    for (int i = 0, j = 0; i < 256; i++, j += 8)
    {
        for (int k = 0; k < 8; k++)
            key_stream[j + k] = i;
    }

    for (int i = 0; i < 8; i++)
        key_stream[2048 + i] = 0;

    return key_stream;
}

uint8_t reverse_bits(uint8_t key)
{
    uint8_t result = 0;

    for (uint8_t i = 0, j = 7; i < 8; i++, j--)
        result |= ((key >> i) & 1) << j;

    return result;
}


void create_general(const char* output_filepath)
{
    if (remove(output_filepath) != 0)
        return;

    FILE* fOutput = fopen(output_filepath, "wb");
    if (!fOutput)
    {
        printf("Cannot open '%s'.\n", output_filepath);
        return;
    }

    for (uint32_t i = 0; i < 8; i++)
        putc('\0', fOutput);

    fclose(fOutput);
}

void create_general000(const char* output_filepath, const char* map_name)
{
    if (remove(output_filepath) != 0)
        return;

    FILE* fOutput = fopen(output_filepath, "wt");
    if (!fOutput)
    {
        printf("Cannot open '%s'.\n", output_filepath);
        return;
    }

    const char* identifier = "Save";

    if (fprintf(fOutput, "%s\n", map_name) < 0 || fprintf(fOutput, "%s\n", identifier) < 0)
    {
        fclose(fOutput);
        return;
    }

    fclose(fOutput);
}
