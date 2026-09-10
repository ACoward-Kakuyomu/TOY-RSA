#ifndef TOY_RSA_DEMO_COMMON_H
#define TOY_RSA_DEMO_COMMON_H

int demo_parse_bits(const char *text, unsigned int *bits);

int demo_run_des_file(int encrypting,
                      const char *key_text,
                      const char *iv_text,
                      const char *input_path,
                      const char *output_path);

int demo_run_rsa_keygen(const char *entropy_path,
                        const char *public_path,
                        const char *private_path,
                        unsigned int bits);

int demo_run_hybrid_encrypt(const char *public_path,
                            const char *entropy_path,
                            const char *input_path,
                            const char *output_path);

int demo_run_hybrid_decrypt(const char *private_path,
                            const char *input_path,
                            const char *output_path);

#endif
