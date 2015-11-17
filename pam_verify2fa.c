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
  char* resp = NULL;
  char* msg;
  const char* me;
  int i;
  int tries=0;

  int ok = 0;
  

  
  for (optargc = 0; optargc < argc; optargc++)
    {
      if (strcasecmp (argv[optargc], "debug") == 0)
	debug = 1;
    }

  pam_get_user(pamh, &me, NULL);

  msg = "Please give your OTP now: ";

  if (debug)
    pam_syslog (pamh, LOG_DEBUG, "sending prompt.");


  while(!ok && tries < MAX_TRIES)
    {
      CURL* easyh;
      int ret;
      char* url = "https://www.uu.se/";
      long code;
      
      retval = pam_prompt (pamh, PAM_PROMPT_ECHO_ON,
			   &resp, "%s", msg);
  
      if (retval != PAM_SUCCESS)
	{
	  _pam_drop (resp);
	  if (retval == PAM_CONV_AGAIN)
	    retval = PAM_INCOMPLETE;
	  return retval;
	}

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
      pam_info(pamh, "\n\nThank you for authenticating.\n\n");
      return PAM_SUCCESS;
    }
  else
    {
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
