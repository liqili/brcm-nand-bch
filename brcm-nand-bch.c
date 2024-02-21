#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "bch.h"

/**
 *
 * This program reads raw NAND image from standard input and updates ECC bytes in the OOB block for each sector.
 * Data layout is as following:
 *
 * 2 KB page, consisting of 4 x 512 B sectors
 * 64 bytes OOB, consisting of 4 x 16 B OOB regions, one for each sector
 *
 * In each OOB region, the first 9 1/2 bytes are user defined and the remaining 6 1/2 bytes are ECC.
 *
 */

#define BCH_T 4
#define BCH_N 13
#define SECTOR_SZ 512
#define OOB_SZ 16
#define SECTORS_PER_PAGE 4
#define OOB_ECC_OFS 9
#define OOB_ECC_LEN 7
#define PAGE_SIZE SECTOR_SZ *SECTORS_PER_PAGE
#define SPARE_SIZE OOB_SZ *SECTORS_PER_PAGE
#define BUFFER_SIZE (SECTOR_SZ + OOB_SZ) * SECTORS_PER_PAGE

// Wide right shift by 4 bits. Preserves the very first 4 bits of the output.
static void shift_half_byte(const uint8_t *src, uint8_t *dest, size_t sz)
{
	// go right to left since input and output may overlap
	unsigned j;
	dest[sz] = src[sz - 1] << 4;
	for (j = sz; j != 0; --j)
		dest[j] = src[j] >> 4 | src[j - 1] << 4;
	dest[0] |= src[0] >> 4;
}

int main(int argc, char *argv[])
{
	unsigned poly = 0;
	char *input_file_name = NULL;
	char *output_file_name = NULL;
	int opt;

	// Parse command line arguments using getopt
	while ((opt = getopt(argc, argv, "i:o:p:")) != -1)
	{
		switch (opt)
		{
		case 'i':
			input_file_name = optarg;
			break;
		case 'o':
			output_file_name = optarg;
			break;
		case 'p':
			poly = strtoul(optarg, NULL, 0);
			break;
		default: /* '?' */
			fprintf(stderr, "Usage: %s -i <input_file> -o <output_file> -p <polynomial_value>\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (input_file_name == NULL || output_file_name == NULL || poly < 0)
	{
		fprintf(stderr, "Usage: %s -i <input_file> -o <output_file> -p <polynomial_value>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	FILE *input_file, *output_file;
	size_t bytes_read;

	// Open the input binary file for reading
	input_file = fopen(input_file_name, "rb");
	if (input_file == NULL)
	{
		perror("Error opening input file");
		exit(EXIT_FAILURE);
	}

	// Open the output binary file for writing
	output_file = fopen(output_file_name, "wb");
	if (output_file == NULL)
	{
		perror("Error opening output file");
		fclose(input_file);
		exit(EXIT_FAILURE);
	}

	struct bch_control *bch = init_bch(BCH_N, BCH_T, poly);
	if (!bch)
		return -1;

	uint8_t page_buffer[BUFFER_SIZE];
	while ((bytes_read = fread(page_buffer, 1, PAGE_SIZE, input_file)) > 0)
	{
		// init spare are as 0xFF
		memset(page_buffer + PAGE_SIZE, 0xFF, SPARE_SIZE);
		// Erased pages have ECC = 0xff .. ff even though there may be user bytes in the OOB region
		int erased_block = 1;
		unsigned i;
		for (i = 0; i != PAGE_SIZE; ++i)
			if (page_buffer[i] != 0xff)
			{
				erased_block = 0;
				break;
			}

		for (i = 0; i != SECTORS_PER_PAGE; ++i)
		{
			const uint8_t *sector_data = page_buffer + SECTOR_SZ * i;
			uint8_t *sector_oob = page_buffer + PAGE_SIZE + OOB_SZ * i;
			if (erased_block)
			{
				// erased page ECC consumes full 7 bytes, including high 4 bits set to 0xf
				memset(sector_oob + OOB_ECC_OFS, 0xff, OOB_ECC_LEN);
			}
			else
			{
				// concatenate input data
				uint8_t buffer[SECTOR_SZ + OOB_ECC_OFS + 1];
				buffer[0] = 0;
				shift_half_byte(sector_data, buffer, SECTOR_SZ);
				shift_half_byte(sector_oob, buffer + SECTOR_SZ, OOB_ECC_OFS);
				// compute ECC
				uint8_t ecc[OOB_ECC_LEN];
				memset(ecc, 0, OOB_ECC_LEN);
				encode_bch(bch, buffer, SECTOR_SZ + OOB_ECC_OFS + 1, ecc);
				// copy the result in its OOB block, shifting right by 4 bits
				shift_half_byte(ecc, sector_oob + OOB_ECC_OFS, OOB_ECC_LEN - 1);
				sector_oob[OOB_ECC_OFS + OOB_ECC_LEN - 1] |= ecc[OOB_ECC_LEN - 1] >> 4;
			}
		}

		fwrite(page_buffer, BUFFER_SIZE, 1, output_file);
	}
}
