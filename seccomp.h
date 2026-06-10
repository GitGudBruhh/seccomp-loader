#ifndef X_SECCOMP_H
#define X_SECCOMP_H


#include <stdio.h>
#include <stdint.h>

#include <linux/filter.h>

#define MAX_BPF_SIZE 32*1024

struct sc_seccomp_file_header {
	// must be 'S', 'C'
	char header[2];
	// must be 0x1
	uint8_t version;
	// only 0x0 or 0x1 support right now
	uint8_t unrestricted;

	uint32_t len_filter;
	uint8_t reserved2[16];
};

void sc_must_read_filter_from_file(FILE *file, uint32_t len_bytes, struct sock_fprog *prog);
FILE* sc_must_read_and_validate_header_from_file(const char *profile_path, struct sc_seccomp_file_header *hdr);
void sc_apply_seccomp_filter(struct sock_fprog *prog);

void die(const char *fmt, ...);

#endif

