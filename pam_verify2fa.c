/*
 * Copyright (c) 2006, 2008 Thorsten Kukuk <kukuk@thkukuk.de>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>

#include <libintl.h>
#include <stddef.h>
#include <sys/types.h>
#include <grp.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>
#include <security/_pam_macros.h>


#include <curl/curl.h>

#define MAX_TRIES 4
#define MAX_EXCLUDES 100

#define ENV_ITEM(n) { (n), #n }
static struct {
  int item;
  const char *name;
} env_items[] = {
  ENV_ITEM(PAM_SERVICE),
  ENV_ITEM(PAM_USER),
  ENV_ITEM(PAM_TTY),
  ENV_ITEM(PAM_RHOST),
  ENV_ITEM(PAM_RUSER),
};


/* Taken from http://creativeandcritical.net/str-replace-c (public domain) */

char *repl_str(const char *str, const char *old, const char *new) {

  /* Adjust each of the below values to suit your needs. */

  /* Increment positions cache size initially by this number. */
  size_t cache_sz_inc = 16;
  /* Thereafter, each time capacity needs to be increased,
   * multiply the increment by this factor. */
  const size_t cache_sz_inc_factor = 3;
  /* But never increment capacity by more than this number. */
  const size_t cache_sz_inc_max = 1048576;

  char *pret, *ret = NULL;
  const char *pstr2, *pstr = str;
  size_t i, count = 0;
  ptrdiff_t *pos_cache = NULL;
  size_t cache_sz = 0;
  size_t cpylen, orglen, retlen, newlen, oldlen = strlen(old);

  /* Find all matches and cache their positions. */
  while ((pstr2 = strstr(pstr, old)) != NULL) {
    count++;

    /* Increase the cache size when necessary. */
    if (cache_sz < count) {
      cache_sz += cache_sz_inc;
      pos_cache = realloc(pos_cache, sizeof(*pos_cache) * cache_sz);
      if (pos_cache == NULL) {
	goto end_repl_str;
      }
      cache_sz_inc *= cache_sz_inc_factor;
      if (cache_sz_inc > cache_sz_inc_max) {
	cache_sz_inc = cache_sz_inc_max;
      }
    }

    pos_cache[count-1] = pstr2 - str;
    pstr = pstr2 + oldlen;
  }

  orglen = pstr - str + strlen(pstr);

  /* Allocate memory for the post-replacement string. */
  if (count > 0) {
    newlen = strlen(new);
    retlen = orglen + (newlen - oldlen) * count;
  } else retlen = orglen;
  ret = malloc(retlen + 1);
  if (ret == NULL) {
    goto end_repl_str;
  }

  if (count == 0) {
    /* If no matches, then just duplicate the string. */
    strcpy(ret, str);
  } else {
    /* Otherwise, duplicate the string whilst performing
     * the replacements using the position cache. */
    pret = ret;
    memcpy(pret, str, pos_cache[0]);
    pret += pos_cache[0];
    for (i = 0; i < count; i++) {
      memcpy(pret, new, newlen);
      pret += newlen;
      pstr = str + pos_cache[i] + oldlen;
      cpylen = (i == count-1 ? orglen : pos_cache[i+1]) - pos_cache[i] - oldlen;
      memcpy(pret, pstr, cpylen);
      pret += cpylen;
    }
    ret[retlen] = '\0';
  }

 end_repl_str:
  /* Free the cache and return the post-replacement string,
   * which will be NULL in the event of an error. */
  free(pos_cache);
  return ret;
}

/* end of string replace implementation */


#define _(str) gettext(str)

static int
call (const char *pam_type, pam_handle_t *pamh,
	   int argc, const char **argv)
{
  struct group* grp;
  
  int debug = 0;
  int quiet = 0;
  int use_stdout = 0;
  int optargc;
  int retval;

  const char* me;
  int i;
  int tries=0;

  char* excludeptr = NULL;
  char* excluded[MAX_EXCLUDES];

  int ok = 0;

  const char* urlptr = NULL;
  excluded[0] = 0;

  
  for (optargc = 0; optargc < argc; optargc++)
    {
      if (strcasecmp (argv[optargc], "debug") == 0)
	debug = 1;

      if (strncasecmp (argv[optargc], "url=", 4) == 0)
	urlptr = argv[optargc]+4;

      if (strncasecmp (argv[optargc], "exclude=", 8) == 0)
	{
	  /* Make array of pointers to excluded usernames */
	  int i = 0;
	  int exlen = strlen(argv[optargc]+8)+1;
	  excludeptr = alloca(exlen);
	  strncpy(excludeptr, argv[optargc]+8, exlen);

	  while (excludeptr && *excludeptr && i<MAX_EXCLUDES)
	    excluded[i++] = strsep(&excludeptr, ",");

	  /* Did we fill all slots? */
	  if (i == MAX_EXCLUDES)
	    {
	      pam_syslog (pamh, LOG_WARNING, "Too many users excluded.");
	      return PAM_SYSTEM_ERR;                
	    }	
	  else
	    excluded[i] = NULL;

	}
    }

  /* URL parameter given? */
  if (!urlptr)
    {
      pam_syslog (pamh, LOG_WARNING, "No URL given for verification.");

      pam_info(pamh, "System is not open right now, sorry!\n"); 
      return PAM_SYSTEM_ERR;     
    }

  /* Get user */
  pam_get_user(pamh, &me, NULL);

  if (!me)
    {
      pam_syslog (pamh, LOG_WARNING, "Failed to get user.");
      return PAM_SYSTEM_ERR;
    }

  if (debug)
    pam_syslog (pamh, LOG_DEBUG, "Checking 2FA for user %s", me);

  /* White listed? */
  i=0;

  if (debug)
    pam_syslog (pamh, LOG_DEBUG, "checking excludes.");
  
  while(excluded[i])
    {
      int len = strlen(excluded[i]);

      if (debug)
	pam_syslog (pamh, LOG_DEBUG, "exclude: %s", excluded[i]);

      if (!strncasecmp(me, excluded[i++], len+1))
	{
	  pam_info(pamh, "\nYou are excluded from 2FA.\n", excluded[i-1], me);
	  return PAM_SUCCESS;	  
	}
    }
  
  if (debug)
    pam_syslog (pamh, LOG_DEBUG, "sending prompt.");


  while(!ok && tries < MAX_TRIES)
    {
      CURL* easyh;
      char* resp;
      char* msg = "Please give your OTP now:";
      int ret;
      char* url = NULL;
      char* tmps = NULL;
      long code;
      int bufsize = 0;

      /* Prompt for and get string */

      retval = pam_prompt (pamh, PAM_PROMPT_ECHO_ON,
			   &resp, "%s", msg);
     
      if (retval != PAM_SUCCESS)
	{
	  pam_syslog (pamh, LOG_WARNING, "pam_prompt failed while talking to %s.", me);
	  
	  _pam_drop (resp);
	  if (retval == PAM_CONV_AGAIN)
	    retval = PAM_INCOMPLETE;
	  return retval;
	}


      tmps = resp;

      tmps = repl_str(urlptr, "%USER%", me);
      if (!tmps)
	return PAM_BUF_ERR;

      url = repl_str(tmps, "%FACTOR%", resp);
      free (tmps);

      if (!url)
	return PAM_BUF_ERR;

      easyh = curl_easy_init();

      ret = curl_easy_setopt(easyh, CURLOPT_URL, url);

      if (ret)
	{
	  curl_easy_cleanup(easyh);
	  pam_info(pamh, "Couldn't authenticate you, sorry!\n");
	  return PAM_AUTH_ERR;	  
	}

      ret = curl_easy_perform(easyh);

      if (ret)
	{
	  curl_easy_cleanup(easyh);
	  pam_info(pamh, "Couldn't authenticate you, sorry!\n");
	  return PAM_AUTH_ERR;
	}
      
      ret = curl_easy_getinfo(easyh, CURLINFO_RESPONSE_CODE, &code);
      curl_easy_cleanup(easyh);
      
      if (ret)
	{
	  pam_info(pamh, "Couldn't authenticate you, sorry!\n");
	  return PAM_AUTH_ERR;
	}
      
      if ( 200 != code)
	{
	  pam_info(pamh, "%s", "\nThat seems incorrect.\n\n");
	  tries++;
	}
      else
	ok = 1;
    }

  if ( ok )
    {
      if (debug)
	pam_syslog (pamh, LOG_DEBUG, "accepted authentication for %s.", me);

      pam_info(pamh, "\n\nThank you for authenticating.\n\n");
      return PAM_SUCCESS;
    }
  else
    {
      if (debug)
	pam_syslog (pamh, LOG_DEBUG, "failing authentication for %s.", me);

      pam_info(pamh, "Couldn't authenticate you, sorry!\n");
      return PAM_AUTH_ERR;
    }

  
  return PAM_SUCCESS;

}

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pamh, int flags,
		     int argc, const char **argv)
{
  return call ("auth", pamh, argc, argv);
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t *pamh , int flags ,
		int argc , const char **argv )
{
  return PAM_IGNORE;
}

/* password updating functions */

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
		 int argc, const char **argv)
{
  if (flags & PAM_PRELIM_CHECK)
    return PAM_SUCCESS;
  return call ("password", pamh, argc, argv);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags ,
		 int argc, const char **argv)
{
  return call ("account", pamh, argc, argv);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags ,
		    int argc, const char **argv)
{
  return call ("open_session", pamh, argc, argv);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags ,
		     int argc, const char **argv)
{
  return call ("close_session", pamh, argc, argv);
}

#ifdef PAM_STATIC
struct pam_module _pam_exec_modstruct = {
  "pam_exec",
  pam_sm_authenticate,
  pam_sm_setcred,
  pam_sm_acct_mgmt,
  pam_sm_open_session,
  pam_sm_close_session,
  pam_sm_chauthtok,
};
#endif
