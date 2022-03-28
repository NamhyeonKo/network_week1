#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

uint32_t convert(uint32_t x){
	uint32_t r;
	r = ntohl(x);
	return r;
}

int main(int argc, char* argv[]){
	FILE *fp1, *fp2;
	uint32_t a1, a2;

	if(argc!=3){
		printf("argc error\n");
		return -1;
	}

	fp1 = fopen(argv[1],"r");
	fp2 = fopen(argv[2],"r");

	if(fp1 == NULL || fp2 == NULL){
		printf("file error\n");
	}
	
	fread(&a1,sizeof(uint32_t),1,fp1);
	fread(&a2,sizeof(uint32_t),1,fp2);

	a1 = convert(a1);
	a2 = convert(a2);

	printf("%d(0x%x) + %d(0x%x) = %d(0x%x)\n",a1,a1,a2,a2,a1+a2,a1+a2);

	fclose(fp1);
	fclose(fp2);
	
	return 0;
}
