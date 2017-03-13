#include <sys/types.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <utils.hh>
#include <swap-endian.hh>

const uint32_t magic = 0x4d455247; // "MERG"
const uint32_t version = 1;

struct Instance
{
	uint32_t *bits;
	size_t bitVectorSize;
	uint64_t id;
	time_t last_time;

	bool initialized;
};

static Instance g_instance;


static void write_report(unsigned int idx)
{
	(void)mkdir("/tmp/kcov-data", 0755);

	std::string out = fmt("/tmp/kcov-data/%016llx", (long long)g_instance.id);
	std::string tmp = fmt("%s.%u", tmp.c_str(), idx);
	FILE *fp = fopen(tmp.c_str(), "w");

	// What to do?
	if (!fp)
		return;

	fwrite(&magic, sizeof(magic), 1, fp);
	fwrite(&version, sizeof(version), 1, fp);
	fwrite(g_instance.bits, sizeof(uint32_t), g_instance.bitVectorSize, fp);

	fclose(fp);
	rename(tmp.c_str(), out.c_str());
}

static void write_at_exit(void)
{
	write_report(0);
}

extern "C" void kcov_dyninst_binary_init(uint64_t id, size_t vectorSize)
{
	g_instance.bits = (uint32_t *)malloc(vectorSize * sizeof(uint32_t));
	g_instance.bitVectorSize = vectorSize;
	g_instance.id = id;
	g_instance.last_time = time(NULL);

	atexit(write_at_exit);
	g_instance.initialized = true;
}

extern "C" void kcov_dyninst_binary_report_address(unsigned int bitIdx)
{
	unsigned int wordIdx = bitIdx / 32;
	unsigned int offset = bitIdx % 32;

	if (!g_instance.initialized)
	{
		fprintf(stderr, "kcov: Library not initialized yet, missing point %u\n", bitIdx);
		return;
	}

	if (wordIdx >= g_instance.bitVectorSize)
	{
		fprintf(stderr, "kcov: INTERNAL ERROR: Index out of bounds (%u vs %zu)\n",
				wordIdx, g_instance.bitVectorSize);
		return;
	}

	// Update the bit atomically
	uint32_t *p = &g_instance.bits[wordIdx];

	// Already hit?
	if (*p & (1 << offset))
		return;

	uint32_t val, newVal;
	do
	{
		val = *p;
		newVal = val | (1 << offset);

	} while (!__sync_bool_compare_and_swap(p, val, newVal));


	// Write out the report
	time_t now = time(NULL);
	if (now - g_instance.last_time >= 2)
	{
		write_report(bitIdx);
		g_instance.last_time = now;
	}
}
