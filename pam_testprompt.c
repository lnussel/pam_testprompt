#if 0
set -- gcc -o ${0%%.*}.so -Wall -g -O2 -fPIC -shared $0
echo "$@"
exec "$@"
exit 1
#endif
/*
 * Copyright (C) 2005-2007 SUSE Linux Products GmbH
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <security/pam_appl.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD
#include <security/pam_modules.h>

#ifdef HAVE_GCCVISIBILITY
#  define DLLEXPORT __attribute__ ((visibility("default")))
#  define DLLLOCAL __attribute__ ((visibility("hidden")))
#else
#  define DLLEXPORT
#  define DLLLOCAL
#endif

#ifndef PAM_EXTERN
#  define PAM_EXTERN
#endif

char file[1024];
int retval;

#define DIMOF(x) (sizeof(x)/sizeof(x[0]))

static void freeresp(struct pam_response* resp, unsigned num)
{
	unsigned i;
	if(!resp)
		return;

	for(i = 0; i < num; ++i)
	{
		if(resp[i].resp)
			memset(resp[i].resp, 0, strlen(resp[i].resp));
		free(resp[i].resp);
	}
	free(resp);
}

static void freemsg(struct pam_message* msg, unsigned num)
{
	unsigned i;
	if(!msg)
		return;

	for(i = 0; i < num; ++i)
	{
		free((char*)msg[i].msg);
		msg[i].msg = NULL;
	}
}

#ifndef __linux__
static char* strndup(const char* str, size_t len)
{
	if(strlen(str) < len)
	{
		return strdup(str);
	}
	else
	{
		char* s = malloc(len+1);
		memcpy(s, str, len);
		s[len] = 0;
		return s;
	}
}
#endif

#define IF_PAM_(x) \
	if(!strcmp(buf, "PAM_" #x)) \
	{ \
		msg[num_msg].msg_style = PAM_##x; \
		msg[num_msg].msg = strndup(s, strlen(s)-1); \
		++num_msg; \
	}

static int converse(pam_handle_t * pamh)
{
	const struct pam_conv *conv;
	int ret;
	char* tmp;
	FILE* fh;

	syslog(LOG_WARNING, "%s %s uid %d, gid %d, euid %d", __FILE__, __FUNCTION__, getuid(), getgid(), geteuid());

	ret = pam_get_item(pamh, PAM_USER, (const void**)(char*)&tmp);
	if(ret == PAM_SUCCESS)
	{
		syslog(LOG_WARNING, "%s %s user %s", __FILE__, __FUNCTION__, tmp);
	}

	ret = pam_get_item(pamh, PAM_TTY, (const void**)(char*)&tmp);
	if(ret == PAM_SUCCESS)
	{
		syslog(LOG_WARNING, "%s %s tty %s", __FILE__, __FUNCTION__, tmp);
	}

	ret = pam_get_item(pamh, PAM_CONV, (const void**)(char*)&conv);
	if(ret != PAM_SUCCESS)
	{
		syslog(LOG_WARNING, "%s %s %d no conversation function: %s",
				__FILE__, __FUNCTION__, getuid(), pam_strerror(pamh, ret));
		return ret;
	}

	fh = fopen(file, "r");
	if(fh)
	{
		struct pam_message msg[32];
		const struct pam_message *pmsg[DIMOF(msg)];
		struct pam_response *resp = NULL;
		char buf[1024];
		unsigned i;
		unsigned num_msg = 0;

		for(i = 0; i < DIMOF(pmsg); ++i)
			pmsg[i] = &msg[i];

		while(fgets(buf, sizeof(buf), fh))
		{
			char* s;

			if(*buf != '\n')
			{
				s = strchr(buf, ' ');
				if(s)
				{
					*s++ = 0;
					IF_PAM_(PROMPT_ECHO_OFF)
					else IF_PAM_(PROMPT_ECHO_ON)
					else IF_PAM_(TEXT_INFO)
					else IF_PAM_(ERROR_MSG)
					else
					{
						syslog(LOG_WARNING, "%s %s unknown prompt %s", __FILE__, __FUNCTION__, buf);
					}
				}
			}
			else
			{
				syslog(LOG_WARNING, "starting conversation");
				ret = conv->conv(num_msg, pmsg, &resp, conv->appdata_ptr);

				if(ret != PAM_SUCCESS)
				{
					syslog(LOG_WARNING, "conversation error: %s", pam_strerror(pamh, ret));
					// in error case caller is responsible
					// freeresp(resp, num_msg);
					return PAM_CONV_ERR;
				}

				if(!resp)
				{
					syslog(LOG_WARNING, "conversation error, response NULL");
					return PAM_CONV_ERR;
				}

				for(i = 0; i < num_msg; ++i)
				{
					syslog(LOG_WARNING, "%s = '%s'", msg[i].msg, resp[i].resp?resp[i].resp:"");
				}
				syslog(LOG_WARNING, "conversation done");

				freeresp(resp, num_msg);
				freemsg(msg, num_msg);
				num_msg = 0;
			}
		}

		fclose(fh);
	}

	return retval;
}

#ifndef PAM_AUTHTOK_RECOVERY_ERR
#define PAM_AUTHTOK_RECOVERY_ERR PAM_AUTHTOK_RECOVER_ERR
#endif

#define RET(x) { #x, x }
static struct retstr2num_s
{
	const char* s;
	int i;
} ret_str2num[] =
{
	RET(PAM_SUCCESS),
	RET(PAM_OPEN_ERR),
	RET(PAM_SYMBOL_ERR),
	RET(PAM_SERVICE_ERR),
	RET(PAM_SYSTEM_ERR),
	RET(PAM_BUF_ERR),
	RET(PAM_PERM_DENIED),
	RET(PAM_AUTH_ERR),
	RET(PAM_CRED_INSUFFICIENT),
	RET(PAM_AUTHINFO_UNAVAIL),
	RET(PAM_USER_UNKNOWN),
	RET(PAM_MAXTRIES),
	RET(PAM_NEW_AUTHTOK_REQD),
	RET(PAM_ACCT_EXPIRED),
	RET(PAM_SESSION_ERR),
	RET(PAM_CRED_UNAVAIL),
	RET(PAM_CRED_EXPIRED),
	RET(PAM_CRED_ERR),
	RET(PAM_NO_MODULE_DATA),
	RET(PAM_CONV_ERR),
	RET(PAM_AUTHTOK_ERR),
	RET(PAM_AUTHTOK_RECOVERY_ERR),
	RET(PAM_AUTHTOK_LOCK_BUSY),
	RET(PAM_AUTHTOK_DISABLE_AGING),
	RET(PAM_TRY_AGAIN),
	RET(PAM_IGNORE),
	RET(PAM_ABORT),
	RET(PAM_AUTHTOK_EXPIRED),
	RET(PAM_MODULE_UNKNOWN),
	RET(PAM_BAD_ITEM),
	RET(PAM_CONV_AGAIN),
	RET(PAM_INCOMPLETE),
	{ NULL, 0}
};
#undef RET

static void parse_args(const char* type, int argc, const char **argv)
{
	int i;

	file[0] = 0;
	retval = PAM_SUCCESS;

	for(i=0; i < argc; ++i)
	{
		if(!strncmp(argv[i], "file=", 5))
		{
			strncat(file, argv[i]+5, sizeof(file));
		}
		else if(!strncmp(argv[i], "ret=", 4))
		{
			int j;
			const char* val = argv[i]+4;
			for(j = 0; ret_str2num[j].s; ++j)
			{
				if(!strcmp(val, ret_str2num[j].s))
				{
					retval = ret_str2num[j].i;
					syslog(LOG_WARNING, "%s %s retval %s=%d", __FILE__, __FUNCTION__, val, retval);
					break;
				}
			}
			if(!ret_str2num[j].s)
			{
				syslog(LOG_WARNING, "%s %s invalid return value %s", __FILE__, __FUNCTION__, val);
			}
		}
		else
		{
				syslog(LOG_WARNING, "%s %s unknown option %s", __FILE__, __FUNCTION__, argv[i]);
		}
	}

	if(!*file)
		snprintf(file, sizeof(file), "/etc/security/pam_testprompt%s%s.conf", type?"_":"", type?type:"");
}

DLLEXPORT PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh, int flags,int argc, const char **argv)
{
	char flagstr[1024] = "";

	if(flags&PAM_SILENT)
		strncat(flagstr, " PAM_SILENT", sizeof(flagstr)-strlen(flagstr)-1);
	if(flags&PAM_DISALLOW_NULL_AUTHTOK)
		strncat(flagstr, " PAM_DISALLOW_NULL_AUTHTOK", sizeof(flagstr)-strlen(flagstr)-1);

	syslog(LOG_WARNING, "%s %s uid:%d euid:%d%s", __FILE__, __FUNCTION__, getuid(), geteuid(), flagstr);

	parse_args("auth", argc, argv);

	return converse(pamh);
}

DLLEXPORT PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	char flagstr[1024] = "";

	if(flags&PAM_SILENT)
		strncat(flagstr, " PAM_SILENT", sizeof(flagstr)-strlen(flagstr)-1);
	if(flags&PAM_ESTABLISH_CRED)
		strncat(flagstr, " PAM_ESTABLISH_CRED", sizeof(flagstr)-strlen(flagstr)-1);
	if(flags&PAM_DELETE_CRED)
		strncat(flagstr, " PAM_DELETE_CRED", sizeof(flagstr)-strlen(flagstr)-1);
	if(flags&PAM_REINITIALIZE_CRED)
		strncat(flagstr, " PAM_REINITIALIZE_CRED", sizeof(flagstr)-strlen(flagstr)-1);
	if(flags&PAM_REFRESH_CRED)
		strncat(flagstr, " PAM_REFRESH_CRED", sizeof(flagstr)-strlen(flagstr)-1);

	syslog(LOG_WARNING, "%s %s uid:%d euid:%d%s", __FILE__, __FUNCTION__, getuid(), geteuid(), flagstr);

	parse_args(NULL, argc, argv);

	return retval;
}

DLLEXPORT PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	syslog(LOG_WARNING, "%s %s uid:%d euid:%d", __FILE__, __FUNCTION__, getuid(), geteuid());

	parse_args("session", argc, argv);

	return converse(pamh);
}

DLLEXPORT PAM_EXTERN int pam_sm_close_session(pam_handle_t * pamh, int flags, int argc, const char **argv)
{
	syslog(LOG_WARNING, "%s %s uid:%d euid:%d", __FILE__, __FUNCTION__, getuid(), geteuid());

	parse_args("session", argc, argv);

	return retval;
}

DLLEXPORT PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	char flagstr[1024] = "";

	if(flags&PAM_SILENT)
		strncat(flagstr, " PAM_SILENT", sizeof(flagstr)-strlen(flagstr)-1);

	syslog(LOG_WARNING, "%s %s%s", __FILE__, __FUNCTION__, flagstr);

	parse_args("account", argc, argv);

	return retval;
}

DLLEXPORT PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	char flagstr[1024] = "";

	if(flags&PAM_SILENT)
		strncat(flagstr, " PAM_SILENT", sizeof(flagstr)-strlen(flagstr)-1);
	if(flags&PAM_CHANGE_EXPIRED_AUTHTOK)
		strncat(flagstr, " PAM_CHANGE_EXPIRED_AUTHTOK", sizeof(flagstr)-strlen(flagstr)-1);
	if(flags&PAM_UPDATE_AUTHTOK)
		strncat(flagstr, " PAM_UPDATE_AUTHTOK", sizeof(flagstr)-strlen(flagstr)-1);
	if(flags&PAM_PRELIM_CHECK)
		strncat(flagstr, " PAM_PRELIM_CHECK", sizeof(flagstr)-strlen(flagstr)-1);

	syslog(LOG_WARNING, "%s %s uid:%d euid%d%s", __FILE__, __FUNCTION__, getuid(), geteuid(), flagstr);

	parse_args("password", argc, argv);

	if(flags & PAM_UPDATE_AUTHTOK)
		return converse(pamh);

	return PAM_SUCCESS;
}
