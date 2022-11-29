#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <net/if.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>

static __be32 in_aton(const char *str)
{
	unsigned int l;
	unsigned int val;
	int i;

	l = 0;
	for (i = 0; i < 4; i++)	{
		l <<= 8;
		if (*str != '\0') {
			val = 0;
			while (*str != '\0' && *str != '.' && *str != '\n') {
				val *= 10;
				val += *str - '0';
				str++;
			}
			l |= val;
			if (*str != '\0')
				str++;
		}
	}
	return htonl(l);
}

int main(int argc, char** argv) {
    printf("CONVERT AN IP ADDRESS: \n");
    printf("IP (ascii): %s", argv[1]);
    printf(" | IP (__be32): %i\n", in_aton(argv[1]));
}