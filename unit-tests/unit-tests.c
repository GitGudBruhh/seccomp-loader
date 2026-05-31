#include <glib.h>

#include "seccomp.c"

static void make_seccomp_profile(struct sc_seccomp_file_header *hdr, int *fd,
				 char **fname)
{
	*fd = g_file_open_tmp(NULL, fname, NULL);
	g_assert_true(*fd > 0);
	int written = write(*fd, hdr, sizeof(struct sc_seccomp_file_header));
	g_assert_true(written == sizeof(struct sc_seccomp_file_header));
}

static void test_must_read_and_validate_header_from_file__happy(void)
{
	struct sc_seccomp_file_header hdr = {
		.header[0] = 'S',
		.header[1] = 'C',
		.version = 1,
	};
	char *profile = NULL;
	int fd = 0;
	make_seccomp_profile(&hdr, &fd, &profile);

	FILE *file =
	    sc_must_read_and_validate_header_from_file(profile, &hdr);
	g_assert_true(file != NULL);
}

static void test_must_read_and_validate_header_from_file__missing_header(void)
{
	struct sc_seccomp_file_header hdr = {};

	if (g_test_subprocess()) {
		char *profile = NULL;
		int fd = 0;
		make_seccomp_profile(&hdr, &fd, &profile);
		FILE *file = sc_must_read_and_validate_header_from_file(profile, &hdr);
		g_assert_not_reached();
		// check null
		g_assert_null(file);
	}

	g_test_trap_subprocess(NULL, 0, 0);
	g_test_trap_assert_failed();
	g_test_trap_assert_stderr("unexpected seccomp header: 00\n");
}

static void __attribute__((constructor)) init(void)
{
	g_test_add_func("/seccomp/must_read_and_validate_header_from_file/happy",
	     test_must_read_and_validate_header_from_file__happy);
	g_test_add_func("/seccomp/must_read_and_validate_header_from_file/missing_header",
	     test_must_read_and_validate_header_from_file__missing_header);

}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	return g_test_run();
}


