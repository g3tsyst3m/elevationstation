#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[])
{

	unsigned char b33fy[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50";

	const int lenny = sizeof(b33fy) / sizeof(b33fy[0]);
	unsigned int onesnzeros[lenny];
	unsigned char shifted[lenny];
	unsigned char shiftright[lenny];
	for (int b = 0; b < lenny - 1; b++)
	{
		printf("==================================\n");
		printf("original: x%02hhx\n", b33fy[b]);
		printf("shiftright: x%02hhx\n", b33fy[b] >> 1);
		shiftright[b] = b33fy[b] >> 1;

		shifted[b] = b33fy[b] >> 1;
		if ((b33fy[b] & 1) == 1)
		{
			printf("1\n");
			onesnzeros[b] = 1;
			shifted[b] = (shifted[b] << 1) + 1;
		}
		else
		{
			printf("0\n");
			onesnzeros[b] = 0;
			shifted[b] = (shifted[b] << 1);
		}
		printf("back to original (shleft): x%02hhx\n", shifted[b]);
		printf("==================================\n");

	}
	printf("final encoded s h 3 ! ! c 0 d 3: \n\n");
        printf("char b33fy[] = \n");
        int counter=1;
        
	for (int x = 0; x < lenny - 1; x++)
	{
                if (counter == 1)
                {
                    printf("\"");
                }
		printf("\\x%x", shiftright[x]);
                if (counter >= 14)
                {
                    printf("\"\n");
                    counter=0;
                }
                counter++;

	}
        printf("\";\n\n");

counter = 1;
printf("unsigned int onesnzeros[] = \n\n");
printf("{");
        for (int x = 0; x < lenny - 1; x++)
        {
                printf("%d", onesnzeros[x]);
                if (x < lenny-2)
                printf(",");
                if (counter >= 14)
                {
                    printf("\n");
                    counter=0;
                }
                counter++;

        }
        printf("};\n");



    return 0;
}

