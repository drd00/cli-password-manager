#include <bsd/readpassphrase.h>
#include <sodium.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define MAX_DATA_LENGTH 2048
#define MAX_N_PASSWORDS 512

typedef struct {
    char platform[MAX_DATA_LENGTH];
    char username[MAX_DATA_LENGTH];
    char password[MAX_DATA_LENGTH];
    size_t platform_len;
    size_t username_len;
    size_t password_len;
} DBEntry;

typedef struct {
    int n_entries;
    unsigned char nonce[crypto_stream_xchacha20_NONCEBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char pwdhash[crypto_generichash_BYTES];
} DBMetadata;

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
            return -1;
        }
    }

    return has_lower + has_upper + has_digit + has_special;
}

int password_correct_format(const char *password) {
    return (get_charset_size(password) != -1);
}

char *read_message(void) {
    size_t buffer_size = MAX_DATA_LENGTH;
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
    if (length > 0 && buffer[length - 1] == '\n') {
        buffer[length - 1] = '\0';
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

int derive_key(const char *master_password, unsigned char *salt, unsigned char *key) {
    if (crypto_pwhash(key, crypto_stream_xchacha20_KEYBYTES, master_password, strlen(master_password), salt, crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
        return -1;
    }

    return 0;
}

int write_db(const char *master_password, const char *db_id, DBEntry *pdb_entries, int n_entries) {
    size_t file_path_max_len = 256;
    char file_path[file_path_max_len];
    snprintf(file_path, file_path_max_len, "./%s.pdb", db_id);

    if (remove(file_path) != 0) {
        switch (errno) {
        case ENOENT:
            // File did not exist in the first place
            printf("Overwriting file %s\n", file_path);
            break;
        case EACCES:
            // Permission denied
            fprintf(stderr, "Error writing to file %s: permission denied.\n", file_path);
            return -1;
        case EBUSY:
            // File currently in use
            fprintf(stderr, "Error writing to file %s: file currently in use.\n", file_path);
            return -1;
        default:
            // Unknown error
            fprintf(stderr, "Error writing to file %s, ERRNO: %d\n", file_path, errno);
            return -1;
        }
    }

    DBMetadata *pdb_metadata = (DBMetadata *)malloc(sizeof(DBMetadata));
    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof salt);
    unsigned char nonce[crypto_stream_xchacha20_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);
    unsigned char *key = sodium_allocarray(crypto_stream_xchacha20_KEYBYTES, sizeof(unsigned char));
    if (derive_key(master_password, salt, key) != 0) {
        fprintf(stderr, "Error occurred in generating secret key from password: %s\n", strerror(errno));
        sodium_free(key);
        free(pdb_metadata);
        return -1;
    }

    /*
        Hash of master password for verification
    */
    unsigned char hash[crypto_generichash_BYTES];
    crypto_generichash(hash, sizeof hash, (unsigned char *)master_password, strlen(master_password), NULL, 0);

    /*
        Copy salt, nonce and hash of master password to
    */
    memcpy(pdb_metadata->salt, salt, crypto_pwhash_SALTBYTES);
    memcpy(pdb_metadata->nonce, nonce, crypto_stream_xchacha20_NONCEBYTES);
    memcpy(pdb_metadata->pwdhash, hash, crypto_generichash_BYTES);
    pdb_metadata->n_entries = n_entries;

    size_t out_size = MAX_N_PASSWORDS * sizeof(DBEntry);
    unsigned char *ciphertext = (unsigned char *)malloc(out_size);
    if (pdb_entries != NULL) {
        if (crypto_stream_xchacha20_xor(ciphertext, (unsigned char *)pdb_entries, out_size, nonce, key) != 0) {
            sodium_free(key);
            free(ciphertext);
            free(pdb_metadata);
            fprintf(stderr, "Error in encryption\n");
            return -1;
        }
    }

    FILE *file = fopen(file_path, "wb");
    if (!file) {
        sodium_free(key);
        free(ciphertext);
        free(pdb_metadata);
        fprintf(stderr, "Error opening file %s for writing: %s\n", file_path, strerror(errno));
    }

    /*
        Write metadata to file
    */
    size_t written = fwrite(pdb_metadata, 1, sizeof(DBMetadata), file);
    if (written != sizeof(DBMetadata)) {
        sodium_free(key);
        free(ciphertext);
        free(pdb_metadata);
        fprintf(stderr, "Error writing metadata to file %s\n", file_path);
        return -1;
    }

    /*
        Write encrypted database entries as a char array to file
    */
    if (pdb_entries != NULL) {
        written = fwrite(ciphertext, 1, out_size, file);
        if (written != out_size) {
            sodium_free(key);
            free(ciphertext);
            free(pdb_metadata);
            fprintf(stderr, "Error writing encrypted data to file%s\n", file_path);
            return -1;
        }
    }
    fclose(file);
    sodium_free(key);
    free(ciphertext);
    free(pdb_metadata);
    return 0;
}

int verify_password(const char *master_password, const DBMetadata *metadata) {
    unsigned char hash[crypto_generichash_BYTES];
    crypto_generichash(hash, crypto_generichash_BYTES, (unsigned char *)master_password, strlen(master_password), NULL, 0);

    return memcmp(metadata->pwdhash, hash, crypto_generichash_BYTES);
}

int read_db(const char *master_password, const char *db_id, DBEntry *entries, DBMetadata *metadata) {
    char file_path[256];
    snprintf(file_path, sizeof(file_path), "./%s.pdb", db_id);

    FILE *file = fopen(file_path, "rb");
    if (!file) {
        fprintf(stderr, "Error opening file %s for reading: %s\n", file_path, strerror(errno));
        return -1;
    }

    if (fread(metadata, 1, sizeof(DBMetadata), file) != sizeof(DBMetadata)) {
        fprintf(stderr, "Error reading metadata from file %s\n", file_path);
        fclose(file);
        return -1;
    }

    if (metadata->n_entries > 0) {
        // Compare password hashes
        if (verify_password(master_password, metadata) != 0) {
            printf("Error reading DB %s: incorrect master password.\n", db_id);
            fclose(file);
            return -1;
        }

        unsigned char *key = sodium_allocarray(crypto_stream_xchacha20_KEYBYTES, sizeof(unsigned char));
        if (derive_key(master_password, metadata->salt, key) != 0) {
            fprintf(stderr, "Error occurred in generating secret key from password: %s\n", strerror(errno));
            sodium_free(key);
            fclose(file);
            return -1;
        }
        unsigned char *data = (unsigned char *)sodium_malloc(MAX_N_PASSWORDS * sizeof(DBEntry));
        if (fread(data, 1, MAX_N_PASSWORDS * sizeof(DBEntry), file) != (MAX_N_PASSWORDS * sizeof(DBEntry))) {
            fprintf(stderr, "Error reading encrypted data from file%s\n", file_path);
            fclose(file);
            sodium_free(key);
            sodium_free(data);
            return -1;
        }

        if (crypto_stream_xchacha20_xor(data, data, MAX_N_PASSWORDS * sizeof(DBEntry), metadata->nonce, key) != 0) {
            fprintf(stderr, "Error in decryption\n");
            sodium_free(key);
            sodium_free(data);
            return -1;
        }
        sec_memcpy(entries, (DBEntry *)data, MAX_N_PASSWORDS * sizeof(DBEntry));

        for (int i = 0; i < metadata->n_entries; i++) {
            // I am not sure why the null terminator seemingly disappears in the encryption/decryption process
            // This adds it back
            entries[i].platform[entries[i].platform_len] = '\0';
            entries[i].username[entries[i].username_len] = '\0';
            entries[i].password[entries[i].password_len] = '\0';
        }

        sodium_free(key);
        sodium_free(data);
    }

    fclose(file);
    return 0;
}


void create_entry(const char *master_password, DBEntry *entries, DBMetadata *metadata, char *platform, char *username, char *password) {
    if (metadata->n_entries >= MAX_N_PASSWORDS) {
        fprintf(stderr, "Cannot create new entry: maximum number of passwords reached.");
        return;
    }

    DBEntry new_entry;
    sec_memcpy(new_entry.username, username, strlen(username));
    sec_memcpy(new_entry.password, password, strlen(password));
    sec_memcpy(new_entry.platform, platform, strlen(platform));
    new_entry.username_len = strlen(username);
    new_entry.password_len = strlen(password);
    new_entry.platform_len = strlen(platform);

    entries[metadata->n_entries] = new_entry;
    metadata->n_entries++;
}

int create_entry_prompt(const char *master_password, const char *db_id) {
    DBEntry *entries = (DBEntry *)sodium_malloc(MAX_N_PASSWORDS * sizeof(DBEntry));
    DBMetadata metadata;
    if (read_db(master_password, db_id, entries, &metadata) != 0) {
        sodium_free(entries);
        return -1;
    }

    printf("Enter a platform: ");
    char *platform = read_message();
    printf("\nEnter a username: ");
    char *username = read_message();
    printf("\nEnter a password: ");
    char *password = read_password();

    if (platform == NULL || username == NULL || password == NULL) {
        sodium_free(password);
        sodium_free(username);
        sodium_free(platform);
        sodium_free(entries);
        return -1;
    }

    create_entry(master_password, entries, &metadata, platform, username, password);

    int return_val;
    if (write_db(master_password, db_id, entries, metadata.n_entries) != 0) {
        return_val = -1;
    } else {
        return_val = 0;
    }

    sodium_free(entries);
    sodium_free(password);
    sodium_free(username);
    sodium_free(platform);
    return return_val;
}

int read_entries(const char *master_password, const char *db_id) {
    DBEntry *entries = (DBEntry *)sodium_malloc(MAX_N_PASSWORDS * sizeof(DBEntry));
    DBMetadata metadata;
    read_db(master_password, db_id, entries, &metadata);
    if (verify_password(master_password, &metadata) != 0) {
        fprintf(stderr, "Error reading DB %s: incorrect master password.\n", db_id);
        sodium_free(entries);
        return -1;
    }

    int n_entries = metadata.n_entries;
    for (int i = 0; i < n_entries; i++) {
        printf("-------\nEntry %s\n-------\n", entries[i].platform);
        printf("Username: %s\n", entries[i].username);
        printf("Password: %s\n", entries[i].password);
        printf("-------\n");
    }

    sodium_free(entries);
    return 0;
}

int main() {
    if (sodium_init() < 0) {
        return 1;
    }

    printf("Enter a DB name: ");
    char *db_id = read_message();
    char db[MAX_DATA_LENGTH];
    snprintf(db, MAX_DATA_LENGTH, "%s.pdb", db_id);
    char *master_password = read_password();
    if (access(db, F_OK) != -1) {
        // File already exists
        printf("Accessing password DB %s.\n", db_id);
    } else {
        // File does not already exist 
        printf("Password DB %s does not exist or cannot be accessed. Attempting to create a new DB with this name...\n", db_id);
        if (write_db(master_password, db_id, NULL, 0) != 0) {
            sodium_free(master_password);
            sodium_free(db_id);
            return 1;
        }
        printf("DB %s created.\n", db_id);
    }

    while (1) {
        printf("Welcome to Daniel's password manager CLI. You are currently accessing the database:\n%s\n", db_id);
        printf("Press 1 to read the database entries. Press 2 to create a new entry. Press 3 to exit.\nInput: ");
        char *input = read_message();
        if (strcmp(input, "1") == 0) {
            printf("Reading entries:\n");
            if (read_entries(master_password, db_id) != 0) {
                sodium_free(master_password);
                sodium_free(input);
                sodium_free(db_id);
                return 1;
            }
        } else if (strcmp(input, "2") == 0) {
            printf("Create an entry:\n");
            if (create_entry_prompt(master_password, db_id) != 0) {
                sodium_free(master_password);
                sodium_free(input);
                sodium_free(db_id);
                return 1;
            }
        } else {
            printf("Goodbye.\n");
            sodium_free(input);
            break;
        }
    }

    sodium_free(master_password);
    sodium_free(db_id);
    return 0;
}
