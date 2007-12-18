/*
 * lib/utils.c		Utility Functions
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 */

/**
 * @defgroup utils Utilities
 * @{
 */

#include <netlink-local.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <linux/socket.h>

/**
 * Debug level
 */
int nl_debug = 0;

struct nl_dump_params nl_debug_dp = {
	.dp_type = NL_DUMP_FULL,
};

static void __init nl_debug_init(void)
{
	char *nldbg, *end;
	
	if ((nldbg = getenv("NLDBG"))) {
		long level = strtol(nldbg, &end, 0);
		if (nldbg != end)
			nl_debug = level;
	}

	nl_debug_dp.dp_fd = stderr;
}

/**
 * @name Error Code Helpers
 * @{
 */

static char *errbuf;
static int nlerrno;

/** @cond SKIP */
int __nl_error(int err, const char *file, unsigned int line, const char *func,
	       const char *fmt, ...)
{
	char *user_err;
	va_list args;

	if (errbuf) {
		free(errbuf);
		errbuf = NULL;
	}

	nlerrno = err;

	if (fmt) {
		va_start(args, fmt);
		vasprintf(&user_err, fmt, args);
		va_end(args);
	}

#ifdef VERBOSE_ERRORS
	asprintf(&errbuf, "%s:%u:%s: %s (errno = %s)",
		 file, line, func, fmt ? user_err : "", strerror(err));
#else
	asprintf(&errbuf, "%s (errno = %s)",
		 fmt ? user_err : "", strerror(err));
#endif

	if (fmt)
		free(user_err);

	return -err;
}

int __nl_read_num_str_file(const char *path, int (*cb)(long, const char *))
{
	FILE *fd;
	char buf[128];

	fd = fopen(path, "r");
	if (fd == NULL)
		return nl_error(errno, "Unable to open file %s for reading",
				path);

	while (fgets(buf, sizeof(buf), fd)) {
		int goodlen, err;
		long num;
		char *end;

		if (*buf == '#' || *buf == '\n' || *buf == '\r')
			continue;

		num = strtol(buf, &end, 0);
		if (end == buf)
			return nl_error(EINVAL, "Parsing error");

		if (num == LONG_MIN || num == LONG_MAX)
			return nl_error(errno, "Number of out range");

		while (*end == ' ' || *end == '\t')
			end++;

		goodlen = strcspn(end, "#\r\n\t ");
		if (goodlen == 0)
			return nl_error(EINVAL, "Empty string");

		end[goodlen] = '\0';

		err = cb(num, end);
		if (err < 0)
			return err;
	}

	fclose(fd);

	return 0;
}

/** @endcond */

int nl_get_errno(void)
{
	return nlerrno;
}


/**
 * Return error message for an error code
 * @return error message
 */
char *nl_geterror(void)
{
	if (errbuf)
		return errbuf;

	if (nlerrno)
		return strerror(nlerrno);

	return "Sucess\n";
}

/**
 * Print a libnl error message
 * @arg s		error message prefix
 *
 * Prints the error message of the call that failed last.
 *
 * If s is not NULL and *s is not a null byte the argument
 * string is printed, followed by a colon and a blank. Then
 * the error message and a new-line.
 */
void nl_perror(const char *s)
{
	if (s && *s)
		fprintf(stderr, "%s: %s\n", s, nl_geterror());
	else
		fprintf(stderr, "%s\n", nl_geterror());
}

/** @} */

/**
 * @name Unit Pretty-Printing
 * @{
 */

/**
 * Cancel down a byte counter
 * @arg	l		byte counter
 * @arg	unit		destination unit pointer
 *
 * Cancels down a byte counter until it reaches a reasonable
 * unit. The chosen unit is assigned to \a unit.
 * 
 * @return The cancelled down byte counter in the new unit.
 */
double nl_cancel_down_bytes(unsigned long long l, char **unit)
{
	if (l >= 1099511627776LL) {
		*unit = "TiB";
		return ((double) l) / 1099511627776LL;
	} else if (l >= 1073741824) {
		*unit = "GiB";
		return ((double) l) / 1073741824;
	} else if (l >= 1048576) {
		*unit = "MiB";
		return ((double) l) / 1048576;
	} else if (l >= 1024) {
		*unit = "KiB";
		return ((double) l) / 1024;
	} else {
		*unit = "B";
		return (double) l;
	}
}

/**
 * Cancel down a bit counter
 * @arg	l		bit counter
 * @arg unit		destination unit pointer
 *
 * Cancels downa bit counter until it reaches a reasonable
 * unit. The chosen unit is assigned to \a unit.
 *
 * @return The cancelled down bit counter in the new unit.
 */
double nl_cancel_down_bits(unsigned long long l, char **unit)
{
	if (l >= 1099511627776ULL) {
		*unit = "Tbit";
		return ((double) l) / 1099511627776ULL;
	} else if (l >= 1073741824) {
		*unit = "Gbit";
		return ((double) l) / 1073741824;
	} else if (l >= 1048576) {
		*unit = "Mbit";
		return ((double) l) / 1048576;
	} else if (l >= 1024) {
		*unit = "Kbit";
		return ((double) l) / 1024;
	} else {
		*unit = "bit";
		return (double) l;
	}
		
}

/**
 * Cancel down a micro second value
 * @arg	l		micro seconds
 * @arg unit		destination unit pointer
 *
 * Cancels down a microsecond counter until it reaches a
 * reasonable unit. The chosen unit is assigned to \a unit.
 *
 * @return The cancelled down microsecond in the new unit
 */
double nl_cancel_down_us(uint32_t l, char **unit)
{
	if (l >= 1000000) {
		*unit = "s";
		return ((double) l) / 1000000;
	} else if (l >= 1000) {
		*unit = "ms";
		return ((double) l) / 1000;
	} else {
		*unit = "us";
		return (double) l;
	}
}

/** @} */

/**
 * @name Generic Unit Translations
 * @{
 */

/**
 * Convert a character string to a size
 * @arg str		size encoded as character string
 *
 * Converts the specified size as character to the corresponding
 * number of bytes.
 *
 * Supported formats are:
 *  - b,kb/k,m/mb,gb/g for bytes
 *  - bit,kbit/mbit/gbit
 *
 * @return The number of bytes or -1 if the string is unparseable
 */
long nl_size2int(const char *str)
{
	char *p;
	long l = strtol(str, &p, 0);
	if (p == str)
		return -1;

	if (*p) {
		if (!strcasecmp(p, "kb") || !strcasecmp(p, "k"))
			l *= 1024;
		else if (!strcasecmp(p, "gb") || !strcasecmp(p, "g"))
			l *= 1024*1024*1024;
		else if (!strcasecmp(p, "gbit"))
			l *= 1024*1024*1024/8;
		else if (!strcasecmp(p, "mb") || !strcasecmp(p, "m"))
			l *= 1024*1024;
		else if (!strcasecmp(p, "mbit"))
			l *= 1024*1024/8;
		else if (!strcasecmp(p, "kbit"))
			l *= 1024/8;
		else if (!strcasecmp(p, "bit"))
			l /= 8;
		else if (strcasecmp(p, "b") != 0)
			return -1;
	}

	return l;
}

/**
 * Convert a character string to a probability
 * @arg str		probability encoded as character string
 *
 * Converts the specified probability as character to the
 * corresponding probability number.
 *
 * Supported formats are:
 *  - 0.0-1.0
 *  - 0%-100%
 *
 * @return The probability relative to NL_PROB_MIN and NL_PROB_MAX
 */
long nl_prob2int(const char *str)
{
	char *p;
	double d = strtod(str, &p);

	if (p == str)
		return -1;

	if (d > 1.0)
		d /= 100.0f;

	if (d > 1.0f || d < 0.0f)
		return -1;

	if (*p && strcmp(p, "%") != 0)
		return -1;

	return rint(d * NL_PROB_MAX);
}

/** @} */

/**
 * @name Time Translations
 * @{
 */

#ifdef USER_HZ
static uint32_t user_hz = USER_HZ;
#else
static uint32_t user_hz = 100;
#endif

static double ticks_per_usec = 1.0f;

/* Retrieves the configured HZ and ticks/us value in the kernel.
 * The value is cached. Supported ways of getting it:
 *
 * 1) environment variable
 * 2) /proc/net/psched and sysconf
 *
 * Supports the environment variables:
 *   PROC_NET_PSCHED  - may point to psched file in /proc
 *   PROC_ROOT        - may point to /proc fs */ 
static void __init get_psched_settings(void)
{
	char name[FILENAME_MAX];
	FILE *fd;
	int got_hz = 0, got_tick = 0;

	if (getenv("HZ")) {
		long hz = strtol(getenv("HZ"), NULL, 0);

		if (LONG_MIN != hz && LONG_MAX != hz) {
			user_hz = hz;
			got_hz = 1;
		}
	}

	if (!got_hz)
		user_hz = sysconf(_SC_CLK_TCK);

	if (getenv("TICKS_PER_USEC")) {
		double t = strtod(getenv("TICKS_PER_USEC"), NULL);

		ticks_per_usec = t;
		got_tick = 1;
	}
		

	if (getenv("PROC_NET_PSCHED"))
		snprintf(name, sizeof(name), "%s", getenv("PROC_NET_PSCHED"));
	else if (getenv("PROC_ROOT"))
		snprintf(name, sizeof(name), "%s/net/psched",
			 getenv("PROC_ROOT"));
	else
		strncpy(name, "/proc/net/psched", sizeof(name) - 1);

	if ((fd = fopen(name, "r"))) {
		uint32_t tick, us, nom;
		int r = fscanf(fd, "%08x%08x%08x%*08x", &tick, &us, &nom);

		if (4 == r && nom == 1000000 && !got_tick)
			ticks_per_usec = (double)tick/(double)us;
			
		fclose(fd);
	}
}


/**
 * Return the value of HZ
 */
int nl_get_hz(void)
{
	return user_hz;
}


/**
 * Convert micro seconds to ticks
 * @arg us		micro seconds
 * @return number of ticks
 */
uint32_t nl_us2ticks(uint32_t us)
{
	return us * ticks_per_usec;
}


/**
 * Convert ticks to micro seconds
 * @arg ticks		number of ticks
 * @return microseconds
 */
uint32_t nl_ticks2us(uint32_t ticks)
{
	return ticks / ticks_per_usec;
}

long nl_time2int(const char *str)
{
	char *p;
	long l = strtol(str, &p, 0);
	if (p == str)
		return -1;

	if (*p) {
		if (!strcasecmp(p, "min") == 0 || !strcasecmp(p, "m"))
			l *= 60;
		else if (!strcasecmp(p, "hour") || !strcasecmp(p, "h"))
			l *= 60*60;
		else if (!strcasecmp(p, "day") || !strcasecmp(p, "d"))
			l *= 60*60*24;
		else if (strcasecmp(p, "s") != 0)
			return -1;
	}

	return l;
}

/**
 * Convert milliseconds to a character string
 * @arg msec		number of milliseconds
 * @arg buf		destination buffer
 * @arg len		buffer length
 *
 * Converts milliseconds to a character string split up in days, hours,
 * minutes, seconds, and milliseconds and stores it in the specified
 * destination buffer.
 *
 * @return The destination buffer.
 */
char * nl_msec2str(uint64_t msec, char *buf, size_t len)
{
	int i, split[5];
	char *units[] = {"d", "h", "m", "s", "msec"};

#define _SPLIT(idx, unit) if ((split[idx] = msec / unit) > 0) msec %= unit
	_SPLIT(0, 86400000);	/* days */
	_SPLIT(1, 3600000);	/* hours */
	_SPLIT(2, 60000);	/* minutes */
	_SPLIT(3, 1000);	/* seconds */
#undef  _SPLIT
	split[4] = msec;

	memset(buf, 0, len);

	for (i = 0; i < ARRAY_SIZE(split); i++) {
		if (split[i] > 0) {
			char t[64];
			snprintf(t, sizeof(t), "%s%d%s",
				 strlen(buf) ? " " : "", split[i], units[i]);
			strncat(buf, t, len - strlen(buf) - 1);
		}
	}

	return buf;
}

/** @} */

/**
 * @name Link Layer Protocol Translations
 * @{
 */

static struct trans_tbl llprotos[] = {
	{0, "generic"},
	__ADD(ARPHRD_ETHER,ether)
	__ADD(ARPHRD_EETHER,eether)
	__ADD(ARPHRD_AX25,ax25)
	__ADD(ARPHRD_PRONET,pronet)
	__ADD(ARPHRD_CHAOS,chaos)
	__ADD(ARPHRD_IEEE802,ieee802)
	__ADD(ARPHRD_ARCNET,arcnet)
	__ADD(ARPHRD_APPLETLK,atalk)
	__ADD(ARPHRD_DLCI,dlci)
	__ADD(ARPHRD_ATM,atm)
	__ADD(ARPHRD_METRICOM,metricom)
	__ADD(ARPHRD_IEEE1394,ieee1394)
#ifdef ARPHRD_EUI64
	__ADD(ARPHRD_EUI64,eui64)
#endif
	__ADD(ARPHRD_INFINIBAND,infiniband)
	__ADD(ARPHRD_SLIP,slip)
	__ADD(ARPHRD_CSLIP,cslip)
	__ADD(ARPHRD_SLIP6,slip6)
	__ADD(ARPHRD_CSLIP6,cslip6)
	__ADD(ARPHRD_RSRVD,rsrvd)
	__ADD(ARPHRD_ADAPT,adapt)
	__ADD(ARPHRD_ROSE,rose)
	__ADD(ARPHRD_X25,x25)
#ifdef ARPHRD_HWX25
	__ADD(ARPHRD_HWX25,hwx25)
#endif
	__ADD(ARPHRD_PPP,ppp)
	__ADD(ARPHRD_HDLC,hdlc)
	__ADD(ARPHRD_LAPB,lapb)
	__ADD(ARPHRD_DDCMP,ddcmp)
	__ADD(ARPHRD_RAWHDLC,rawhdlc)
	__ADD(ARPHRD_TUNNEL,ipip)
	__ADD(ARPHRD_TUNNEL6,tunnel6)
	__ADD(ARPHRD_FRAD,frad)
	__ADD(ARPHRD_SKIP,skip)
	__ADD(ARPHRD_LOOPBACK,loopback)
	__ADD(ARPHRD_LOCALTLK,localtlk)
	__ADD(ARPHRD_FDDI,fddi)
	__ADD(ARPHRD_BIF,bif)
	__ADD(ARPHRD_SIT,sit)
	__ADD(ARPHRD_IPDDP,ip/ddp)
	__ADD(ARPHRD_IPGRE,gre)
	__ADD(ARPHRD_PIMREG,pimreg)
	__ADD(ARPHRD_HIPPI,hippi)
	__ADD(ARPHRD_ASH,ash)
	__ADD(ARPHRD_ECONET,econet)
	__ADD(ARPHRD_IRDA,irda)
	__ADD(ARPHRD_FCPP,fcpp)
	__ADD(ARPHRD_FCAL,fcal)
	__ADD(ARPHRD_FCPL,fcpl)
	__ADD(ARPHRD_FCFABRIC,fcfb_0)
	__ADD(ARPHRD_FCFABRIC+1,fcfb_1)
	__ADD(ARPHRD_FCFABRIC+2,fcfb_2)
	__ADD(ARPHRD_FCFABRIC+3,fcfb_3)
	__ADD(ARPHRD_FCFABRIC+4,fcfb_4)
	__ADD(ARPHRD_FCFABRIC+5,fcfb_5)
	__ADD(ARPHRD_FCFABRIC+6,fcfb_6)
	__ADD(ARPHRD_FCFABRIC+7,fcfb_7)
	__ADD(ARPHRD_FCFABRIC+8,fcfb_8)
	__ADD(ARPHRD_FCFABRIC+9,fcfb_9)
	__ADD(ARPHRD_FCFABRIC+10,fcfb_10)
	__ADD(ARPHRD_FCFABRIC+11,fcfb_11)
	__ADD(ARPHRD_FCFABRIC+12,fcfb_12)
	__ADD(ARPHRD_IEEE802_TR,tr)
	__ADD(ARPHRD_IEEE80211,ieee802.11)
#ifdef ARPHRD_IEEE80211_PRISM
	__ADD(ARPHRD_IEEE80211_PRISM, ieee802.11_prism)
#endif
#ifdef ARPHRD_VOID
	__ADD(ARPHRD_VOID,void)
#endif
};

char * nl_llproto2str(int llproto, char *buf, size_t len)
{
	return __type2str(llproto, buf, len, llprotos, ARRAY_SIZE(llprotos));
}

int nl_str2llproto(const char *name)
{
	return __str2type(name, llprotos, ARRAY_SIZE(llprotos));
}

/** @} */


/**
 * @name Ethernet Protocol Translations
 * @{
 */

static struct trans_tbl ether_protos[] = {
	__ADD(ETH_P_LOOP,loop)
	__ADD(ETH_P_PUP,pup)
	__ADD(ETH_P_PUPAT,pupat)
	__ADD(ETH_P_IP,ip)
	__ADD(ETH_P_X25,x25)
	__ADD(ETH_P_ARP,arp)
	__ADD(ETH_P_BPQ,bpq)
	__ADD(ETH_P_IEEEPUP,ieeepup)
	__ADD(ETH_P_IEEEPUPAT,ieeepupat)
	__ADD(ETH_P_DEC,dec)
	__ADD(ETH_P_DNA_DL,dna_dl)
	__ADD(ETH_P_DNA_RC,dna_rc)
	__ADD(ETH_P_DNA_RT,dna_rt)
	__ADD(ETH_P_LAT,lat)
	__ADD(ETH_P_DIAG,diag)
	__ADD(ETH_P_CUST,cust)
	__ADD(ETH_P_SCA,sca)
	__ADD(ETH_P_RARP,rarp)
	__ADD(ETH_P_ATALK,atalk)
	__ADD(ETH_P_AARP,aarp)
#ifdef ETH_P_8021Q
	__ADD(ETH_P_8021Q,802.1q)
#endif
	__ADD(ETH_P_IPX,ipx)
	__ADD(ETH_P_IPV6,ipv6)
#ifdef ETH_P_WCCP
	__ADD(ETH_P_WCCP,wccp)
#endif
	__ADD(ETH_P_PPP_DISC,ppp_disc)
	__ADD(ETH_P_PPP_SES,ppp_ses)
	__ADD(ETH_P_MPLS_UC,mpls_uc)
	__ADD(ETH_P_MPLS_MC,mpls_mc)
	__ADD(ETH_P_ATMMPOA,atmmpoa)
	__ADD(ETH_P_ATMFATE,atmfate)
	__ADD(ETH_P_EDP2,edp2)
	__ADD(ETH_P_802_3,802.3)
	__ADD(ETH_P_AX25,ax25)
	__ADD(ETH_P_ALL,all)
	__ADD(ETH_P_802_2,802.2)
	__ADD(ETH_P_SNAP,snap)
	__ADD(ETH_P_DDCMP,ddcmp)
	__ADD(ETH_P_WAN_PPP,wan_ppp)
	__ADD(ETH_P_PPP_MP,ppp_mp)
	__ADD(ETH_P_LOCALTALK,localtalk)
	__ADD(ETH_P_PPPTALK,ppptalk)
	__ADD(ETH_P_TR_802_2,tr_802.2)
	__ADD(ETH_P_MOBITEX,mobitex)
	__ADD(ETH_P_CONTROL,control)
	__ADD(ETH_P_IRDA,irda)
	__ADD(ETH_P_ECONET,econet)
	__ADD(ETH_P_HDLC,hdlc)
};

char *nl_ether_proto2str(int eproto, char *buf, size_t len)
{
	return __type2str(eproto, buf, len, ether_protos,
			    ARRAY_SIZE(ether_protos));
}

int nl_str2ether_proto(const char *name)
{
	return __str2type(name, ether_protos, ARRAY_SIZE(ether_protos));
}

/** @} */

/**
 * @name IP Protocol Translations
 * @{
 */

char *nl_ip_proto2str(int proto, char *buf, size_t len)
{
	struct protoent *p = getprotobynumber(proto);

	if (p) {
		snprintf(buf, len, "%s", p->p_name);
		return buf;
	}

	snprintf(buf, len, "0x%x", proto);
	return buf;
}

int nl_str2ip_proto(const char *name)
{
	struct protoent *p = getprotobyname(name);
	unsigned long l;
	char *end;

	if (p)
		return p->p_proto;

	l = strtoul(name, &end, 0);
	if (l == ULONG_MAX || *end != '\0')
		return -1;

	return (int) l;
}

/** @} */

/**
 * @name Dumping Helpers
 * @{
 */

/**
 * Handle a new line while dumping
 * @arg params		Dumping parameters
 * @arg line		Number of lines dumped already.
 *
 * This function must be called before dumping any onto a
 * new line. It will ensure proper prefixing as specified
 * by the dumping parameters.
 *
 * @note This function will NOT dump any newlines itself
 */
void nl_new_line(struct nl_dump_params *params, int line)
{
	if (params->dp_prefix) {
		int i;
		for (i = 0; i < params->dp_prefix; i++) {
			if (params->dp_fd)
				fprintf(params->dp_fd, " ");
			else if (params->dp_buf)
				strncat(params->dp_buf, " ",
					params->dp_buflen -
					sizeof(params->dp_buf) - 1);
		}
	}

	if (params->dp_nl_cb)
		params->dp_nl_cb(params, line);
}

/**
 * Dump a formatted character string
 * @arg params		Dumping parameters
 * @arg fmt		printf style formatting string
 * @arg ...		Arguments to formatting string
 *
 * Dumps a printf style formatting string to the output device
 * as specified by the dumping parameters.
 */
void nl_dump(struct nl_dump_params *params, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	__dp_dump(params, fmt, args);
	va_end(args);
}

/** @} */

/** @} */
