#include <bsd/readpassphrase.h>
#include <sodium.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#define MAX_DATA_LENGTH 2048

struct DatabaseEntry {
    char data[MAX_DATA_LENGTH];
    size_t data_len;
    char nonce[crypto_stream_xchacha20_NONCEBYTES];
    char salt[crypto_pwhash_SALTBYTES];
};

struct PwdHashEntry {
    char hash[crypto_generichash_BYTES];
};

volatile void *sec_memcpy(volatile void *dst, volatile void *src, size_t len) {
    volatile char *cdst, *csrc;

    cdst = (volatile char *)dst;
    csrc = (volatile char *)src;

    while (len--) {
        cdst[len] = csrc[len];
    }

    return dst;
}

unsigned short alphanum_is_upper(char c) {
    if (c >= 'A' && c <= 'Z') {
        return ('Z' - 'A');
    }

    return 0;
}

unsigned short alphanum_is_lower(char c) {
    if (c >= 'a' && c <= 'z') {
        return ('z' - 'a');
    }

    return 0;
}

unsigned short alphanum_is_num(char c) {
    if (c >= '0' && c <= '9') {
        return ('9' - '0');
    }

    return 0;
}

unsigned short allowed_special_char(char c) {
    // Currently allow *, /, &, ;, @
    if (c == '*' || c == '/' || c == '&' || c == ';' || c == '@') {
        // update this if more characters are added
        return 5;
    }

    return 0;
}

int get_charset_size(const char *password) {
    unsigned short has_lower = 0;
    unsigned short has_upper = 0;
    unsigned short has_digit = 0;
    unsigned short has_special = 0;

    for (int i = 0; password[i] != '\0'; i++) {
        if (alphanum_is_lower(password[i])) {
            has_lower = alphanum_is_lower(password[i]);
        } else if (alphanum_is_upper(password[i])) {
            has_upper = alphanum_is_upper(password[i]);
        } else if (alphanum_is_num(password[i])) {
            has_digit = alphanum_is_num(password[i]);
        } else if (allowed_special_char(password[i])) {
            has_special = allowed_special_char(password[i]);
        } else {
            return NULL;
        }
    }

    return has_lower + has_upper + has_digit + has_special;
}

int password_correct_format(const char *password) {
    return (get_charset_size(password) != NULL);
}

char *read_message(void) {
    size_t buffer_size = 1024;
    char *buffer = (char *)sodium_malloc(buffer_size);
    if (buffer == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    if (fgets(buffer, buffer_size, stdin) == NULL) {
        fprintf(stderr, "Error reading input\n");
        sodium_free(buffer);
        return NULL;
    }

    size_t length = strlen(buffer);
    if (length > 0 && buffer[length-1] == '\n') {
        buffer[length-1] = '\0';
    }

    return buffer;
}

char *read_password(void) {
    size_t buffer_size = 1024;
    char *passbuf = (char *)sodium_malloc(buffer_size);
    if (passbuf == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    char *passphrase = readpassphrase("Enter password: ", passbuf, buffer_size, RPP_REQUIRE_TTY);

    if (passphrase == NULL) {
        fprintf(stderr, "Error reading passphrase.\n");
        sodium_free(passbuf);
        return NULL;
    } else if (!password_correct_format(passphrase)) {
        fprintf(stderr, "Password is not in the correct format.\n");
        sodium_free(passbuf);
        return NULL;
    } else {
        printf("Successfully read password.\n");
    }

    return passbuf;
}

void encrypt(char *data, const char *key, const char *nonce, size_t data_len) {
    crypto_stream_xchacha20_xor(data, data, data_len, nonce, key);
}

void decrypt(char *data, const char *key, const char *nonce, size_t data_len) {
    crypto_stream_xchacha20_xor(data, data, MAX_DATA_LENGTH, nonce, key);
}

void derive_key(const char *master_password, const char *salt, char *key) {
    // TODO: handle possible errors here.
    crypto_pwhash(key, crypto_stream_xchacha20_KEYBYTES, master_password, strlen(master_password), salt, crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT);
}

void write_entry_to_file(const struct DatabaseEntry* file_data, const char *directory, const char *filename) {
    char filepath[256];
    snprintf(filepath, 256, "%s/%s", directory, filename);

    FILE *file = fopen(filepath, "wb");
    if (file == NULL) {
        printf("Error opening file %s.\n", filepath);
        return;
    }
    fwrite(file_data, sizeof(struct DatabaseEntry), 1, file);

    fclose(file);
}

void read_entry_from_file(struct DatabaseEntry* file_data, const char *file_path) {
    FILE *file = fopen(file_path, "rb");
    if (file == NULL) {
        printf("Error opening file %s.\n", file_path);
        return;
    }

    fread(file_data, sizeof(struct DatabaseEntry), 1, file);

    fclose(file);
}

void create_pwdhash(const char *master_password, const char *directory) {
    // create a hash of the master password and compare with a hash in passwdhash file
    unsigned char *hash = sodium_allocarray(crypto_generichash_BYTES, sizeof(unsigned char));
    crypto_generichash(hash, crypto_generichash_BYTES, master_password, strlen((char *)master_password), NULL, 0);

    char filepath[256];
    snprintf(filepath, 256, "%s/%s", directory, "pwdhash");

    FILE *file = fopen(filepath, "wb");
    if (file == NULL) {
        printf("Error opening file %s.\n", filepath);
        return;
    }
    fwrite(hash, sizeof(char), crypto_generichash_BYTES, file);
    fclose(file);

    sodium_free(hash);
}

int verify_pwdhash(const char *master_password, const char *directory) {
    unsigned char *hash = sodium_allocarray(crypto_generichash_BYTES, sizeof(unsigned char));
    crypto_generichash(hash, crypto_generichash_BYTES, master_password, strlen((char *)master_password), NULL, 0);

    char filepath[256];
    snprintf(filepath, 256, "%s/%s", directory, "pwdhash");

    FILE *file = fopen(filepath, "rb");
    if (file == NULL) {
        printf("Error opening file %s.\n", file);
        return;
    }

    unsigned char *read_hash = sodium_allocarray(crypto_generichash_BYTES, sizeof(unsigned char));
    fread(read_hash, sizeof(char), crypto_generichash_BYTES, file);
    int cmp = sodium_memcmp(hash, read_hash, crypto_generichash_BYTES);

    if (cmp >= 0) {
        // hashes are the same
        // make sure to memfree etc.
        
    }
}

void create_entry(const char *master_password) {
    // Read entry data
    char *data = read_message();
    size_t data_len = strlen(data);

    // PBKDF
    unsigned char *salt = sodium_allocarray(crypto_pwhash_SALTBYTES, sizeof(unsigned char));
    randombytes_buf(salt, sizeof salt);

    unsigned char *key = sodium_allocarray(crypto_stream_xchacha20_KEYBYTES, sizeof(unsigned char));
    derive_key(master_password, salt, key);

    // Encrypt data
    unsigned char *nonce = sodium_allocarray(crypto_stream_xchacha20_NONCEBYTES, sizeof(unsigned char));
    randombytes_buf(nonce, sizeof nonce);
    encrypt(data, key, nonce, data_len);

    struct DatabaseEntry entry;
    sec_memcpy(entry.data, data, data_len);
    sec_memcpy(entry.nonce, nonce, crypto_stream_xchacha20_NONCEBYTES);
    sec_memcpy(entry.salt, salt, crypto_pwhash_SALTBYTES);
    entry.data_len = data_len;

    // Compute short hash for file name
    unsigned char *hash = sodium_allocarray(crypto_shorthash_BYTES, sizeof(unsigned char));
    const unsigned char *hash_key = sodium_allocarray(16, sizeof(unsigned char));
    crypto_shorthash_keygen(hash_key);
    crypto_shorthash(hash, data, data_len, hash_key);

    unsigned char *hash_hex = sodium_allocarray((crypto_shorthash_BYTES * 2) + 1, sizeof(unsigned char));
    sodium_bin2hex(hash_hex, ((crypto_shorthash_BYTES * 2) + 1), hash, crypto_shorthash_BYTES);

    // Write
    write_entry_to_file(&entry, "./pwd", hash_hex);

    //sodium_memzero(key, crypto_stream_xchacha20_KEYBYTES);
    // sodium_memzero(data, data_len);
    // sodium_memzero(salt, crypto_pwhash_SALTBYTES);
    // sodium_memzero(nonce, crypto_stream_xchacha20_NONCEBYTES);
    // sodium_memzero(hash_key, 16 * sizeof(unsigned char));
    // sodium_memzero(hash, crypto_shorthash_BYTES);
    // sodium_memzero(hash_hex, ((crypto_shorthash_BYTES * 2) + 1));
    sodium_free(key);
    sodium_free(data);
    sodium_free(salt);
    sodium_free(nonce);
    sodium_free(hash);
    sodium_free(hash_key);
    sodium_free(hash_hex);
}

void read_entry(const char *master_password, const char *file_path) {
    struct DatabaseEntry file_data;
    read_entry_from_file(&file_data, file_path);

    // PBKDF
    unsigned char *key = sodium_allocarray(crypto_stream_xchacha20_KEYBYTES, sizeof(unsigned char));
    derive_key(master_password, file_data.salt, key);

    // Decrypt data
    decrypt(file_data.data, key, file_data.nonce, file_data.data_len);
    file_data.data[file_data.data_len] = '\0';
    printf("Output: %s\n", file_data.data);
    sodium_memzero(&file_data.data, file_data.data_len);
    sodium_memzero(&file_data.data_len, sizeof(size_t));
    sodium_memzero(&file_data.nonce, crypto_stream_xchacha20_NONCEBYTES);
    sodium_memzero(&file_data.salt, crypto_pwhash_SALTBYTES);
}

int main() {
    if (sodium_init() < 0) {
    }
    char *master_password = read_password();
    // assume user wants to create an entry for now
    // create_entry(master_password);
    read_entry(master_password, "./pwd/f7dbb7558d80f129");

    sodium_memzero(master_password, strlen(master_password));
    sodium_free(master_password);
}