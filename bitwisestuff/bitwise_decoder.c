#include <stdio.h>

int main() {

char b33fy[] = 
"\x7e\x24\x41\x72\x78\x74\x60\x0\x0\x0\x20\x28\x20\x28";

unsigned int onesnzeros[] = 

{0,0,1,0,0,0,0,0,0,0,1,1,1,0};

	const int lenny = sizeof(b33fy) / sizeof(b33fy[0]);
	unsigned char shifted[lenny];
	unsigned char shiftright[lenny];
	for (int b = 0; b < lenny - 1; b++)
	{
		shifted[b] = b33fy[b] << 1;
		if (onesnzeros[b] == 1)
		{
			printf("1\n");
			shifted[b] = shifted[b] + 1;
		}
		printf("back to original (shleft): x%02hhx\n", shifted[b]);
		printf("==================================\n");

	}
	printf("final encoded s h 3 ! ! c 0 d 3: \n\n");
        printf("unsigned char b33fy[] = \n");
        int counter=1;
        
	for (int x = 0; x < lenny - 1; x++)
	{
                if (counter == 1)
                {
                    printf("\"");
                }
		printf("\\x%x", shifted[x]);
                if (counter >= 14)
                {
                    printf("\"\n");
                    counter=0;
                }
                counter++;

	}
        printf("\";\n");

    return 0;
}

