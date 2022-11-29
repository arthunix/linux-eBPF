#include "../libbpf-bootstrap/examples/c/sockfilter.h"

/*
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
*/

static struct filter filtering_rules_array[] = {
	{
		.id = 1,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 21 /* FTP */
	},
    {
		.id = 2,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 22 /* SSH */
	},
    {
		.id = 3,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 23 /* TELNET */
	},
    {
		.id = 4,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 25 /* SMTP */
	},
    {
		.id = 5,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 43 /* WHOIS */
	},
    {
		.id = 6,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 53 /* DNS */
	},
    {
		.id = 7,
		.enabled = 0,
		.action = 0, /* DROP */
		.udpopts.enabled = 1,
		.udpopts.dport = 67 /* DHCP */
	},
	{
		.id = 8,
		.enabled = 0,
		.action = 0, /* DROP */
		.udpopts.enabled = 1,
		.udpopts.dport = 68 /* DHCP */
	},
    {
		.id = 9,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 80 /* HTTP */
	},
    {
		.id = 10,
		.enabled = 0,
		.action = 0, /* DROP */
		.udpopts.enabled = 1,
		.udpopts.dport = 80 /* HTTP */
	},
    {
		.id = 11,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 110 /* POP3 */
	},
    {
		.id = 12,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 115 /* FTP */
	},
    {
		.id = 13,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 143 /* IMAP */
	},
    {
		.id = 14,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 443 /* HTTPS */
	},
    {
		.id = 15,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 443 /* HTTPS */
	},
    {
		.id = 16,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 587 /* SMTP SSL */
	},
    {
		.id = 17,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 993 /* IMAP SSL */
	},
	{
		.id = 21,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 21 /* FTP */
	},
    {
		.id = 22,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 22 /* SSH */
	},
    {
		.id = 23,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 23 /* TELNET */
	},
    {
		.id = 24,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 25 /* SMTP */
	},
    {
		.id = 25,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 43 /* WHOIS */
	},
    {
		.id = 26,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 53 /* DNS */
	},
    {
		.id = 27,
		.enabled = 0,
		.action = 0, /* DROP */
		.udpopts.enabled = 1,
		.udpopts.sport = 67 /* DHCP */
	},
	{
		.id = 28,
		.enabled = 0,
		.action = 0, /* DROP */
		.udpopts.enabled = 1,
		.udpopts.sport = 68 /* DHCP */
	},
    {
		.id = 29,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 80 /* HTTP */
	},
    {
		.id = 30,
		.enabled = 0,
		.action = 0, /* DROP */
		.udpopts.enabled = 1,
		.udpopts.sport = 80 /* HTTP */
	},
    {
		.id = 31,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 110 /* POP3 */
	},
    {
		.id = 32,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 115 /* FTP */
	},
    {
		.id = 33,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 143 /* IMAP */
	},
    {
		.id = 34,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 443 /* HTTPS */
	},
    {
		.id = 35,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 443 /* HTTPS */
	},
    {
		.id = 36,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 587 /* SMTP SSL */
	},
    {
		.id = 37,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 993 /* IMAP SSL */
	},
    /* ANOTHER FILTERING RULES */
    {
		.id = 41,
		.enabled = 0,
		.action = 0, /* DROP */
        .dstip = 36949814,        /* ava2.ead.ufscar.br */
        .srcip = 36949814         /* ava2.ead.ufscar.br */
	},
    {
		.id = 42,
		.enabled = 0,
		.action = 0, /* DROP */
        .dstip = 676391354,      /* ava2.ead.ufscar.br */
        .srcip = 676391354       /* ava2.ead.ufscar.br */
	},
    {
		.id = 43,
		.enabled = 0,
		.action = 0, /* DROP */
        .dstip = 2060421320,    /* ava2.ead.ufscar.br */
        .srcip = 2060421320     /* ava2.ead.ufscar.br */
	},
    {
		.id = 44,
		.enabled = 0,
		.action = 0, /* DROP */
        .dstip = 1008258870,       /* ava2.ead.ufscar.br */
        .srcip = 1008258870        /* ava2.ead.ufscar.br */
	}
};