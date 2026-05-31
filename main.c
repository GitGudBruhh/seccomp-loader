#include <stdlib.h>

#include "seccomp.h"

int main(int argc, char **argv) {
	if (argc != 2) {
		die("needs seccomp profile as first argument");
	}

	struct sock_fprog  prog_allow = { 0 };
	struct sc_seccomp_file_header hdr = {0};

	const char *profile_path = argv[1];
	FILE *file  = sc_must_read_and_validate_header_from_file(profile_path, &hdr);
	sc_must_read_filter_from_file(file, hdr.len_filter, &prog_allow);


	sc_apply_seccomp_filter(&prog_allow);
	free(prog_allow.filter);
	fclose(file);
}
