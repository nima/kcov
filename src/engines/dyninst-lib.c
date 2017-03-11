#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void kcov_dyninst_report_address(void *addr)
{
	static FILE *file = NULL;
	uint64_t asInt = (uint64_t)addr;

	// Open the FIFO if it hasn't been created
	if (!file) {
		char *path;

		path = getenv("KCOV_DYNINST_PIPE_PATH");

		if (!path) {
			fprintf(stderr, "kcov-dyninst: Library path not set\n");
			return;
		}

		file = fopen(path, "w");
		if (!file) {
			fprintf(stderr, "kcov-dyninst: Can't open %s\n", path);
			return;
		}
	}

	fwrite(&asInt, sizeof(asInt), 1, file);
}
