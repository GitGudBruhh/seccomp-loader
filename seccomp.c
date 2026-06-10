#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>


#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include <linux/filter.h>
#include <linux/prctl.h>
#include <linux/seccomp.h>

#include "seccomp.h"

void die(const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	exit(1);
}

FILE* sc_must_read_and_validate_header_from_file(const char *profile_path, struct sc_seccomp_file_header *hdr)
{
	FILE *file = fopen(profile_path, "rb");
	if (file == NULL) {
		die("cannot open seccomp filter %s", profile_path);
	}
	size_t num_read = fread(hdr, 1, sizeof(struct sc_seccomp_file_header), file);
	if (ferror(file) != 0) {
		fclose(file);
		die("cannot read seccomp profile %s", profile_path);
	}
	if (num_read < sizeof(struct sc_seccomp_file_header)) {
		fclose(file);
		die("short read on seccomp header: %zu", num_read);
	}
	// check everything in the seccomp file header
	if (hdr->header[0] != 'S' || hdr->header[1] != 'C' ||
		hdr->version != 0x01 ||
		!(hdr->unrestricted == 0x00 || hdr->unrestricted == 0x01)
	) {
		fclose(file);
		die("unexpected seccomp header: %x%x", hdr->header[0], hdr->header[1]);
	}
	if (hdr->len_filter > MAX_BPF_SIZE) {
		fclose(file);
		die("allow filter size too big %u", hdr->len_filter);
	}
	return file;
}

void sc_must_read_filter_from_file(FILE *file, uint32_t len_bytes, struct sock_fprog *prog)
{
	if((len_bytes % sizeof(struct sock_filter)) != 0) {
		fclose(file);
		die("filter size %" PRIu32 " not a multiple of sock_filter size %zu", len_bytes, sizeof(struct sock_filter));
	}

	size_t num_filter_blocks = len_bytes / sizeof(struct sock_filter);
	if(num_filter_blocks > USHRT_MAX) {
		// sock_fprog.len is of type unsigned short
		fclose(file);
		die("filter size too large");
	}

	prog->len = num_filter_blocks;
	prog->filter = (struct sock_filter *)malloc(len_bytes);
	if (prog->filter == NULL) {
		fclose(file);
		die("cannot allocate %u bytes of memory for seccomp filter ", len_bytes);
	}
	size_t num_read = fread(prog->filter, 1, len_bytes, file);
	if (ferror(file)) {
		fclose(file);
		free(prog->filter);
		die("cannot read filter");
	}
	if (num_read != len_bytes) {
		fclose(file);
		free(prog->filter);
		die("short read for filter %zu != %i", num_read, len_bytes);
	}
}

int seccomp(unsigned int operation, unsigned int flags, void *args) {
	errno = 0;
	return syscall(__NR_seccomp, operation, flags, args);
}

void sc_apply_seccomp_filter(struct sock_fprog *prog) {
	int err = seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_LOG, prog);
	if (err != 0) {
		free(prog->filter);
		die("cannot apply seccomp profile");
	}
}

