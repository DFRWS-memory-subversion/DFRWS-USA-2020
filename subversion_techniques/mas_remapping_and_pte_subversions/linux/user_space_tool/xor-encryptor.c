/* xor-encryptor.c -- encrypts with xor
 * Copyright (C) 2019 Patrick Reichenberger
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
#include <stdio.h>

int main(int argc, char *argv[]) {
    FILE *input_file = fopen(argv[1], "rb");
    if (!input_file) {
        fprintf(stderr, "Failed to open input file: %s\n",argv[1]);
        return -1;
    }

    FILE *out_file = fopen(argv[2], "wb");
    if (!out_file) {
        fclose(input_file);
        fprintf(stderr, "Failed to open output file for writing: %s\n", argv[2]);
        return -1;
    }

    char buffer[1024];
    int count;

    while(count = fread(buffer, 1, 1024, input_file)) {
        int i;
        for( i = 0; i < count; ++i) {
            if (buffer[i] != 0x00 && buffer[i] != 0x1a) {
                buffer[i] ^= 0x1a;
            }
        }
        if(fwrite(buffer, 1, count, out_file) != count) {
            fclose(input_file);
            fclose(out_file);
            fprintf(stderr, "Failed to write to disk");
            return -1;
        }
    }
    fclose(input_file);
    fclose(out_file);
    return 0;
}
