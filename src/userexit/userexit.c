/***********************************************************************
* ADSTAR Distributed Storage Manager (adsm)                            * 
* Server Component                                                     *
*                                                                      *
* 5639-B9300 (C) Copyright IBM Corporation 1997 (Unpublished)          * 
***********************************************************************/

/***********************************************************************
 * Name:            userExitSample.c
 *
 * Description:     Example user-exit program that is invoked by
 *		    the ADSM V3 Server 
 *
 * Environment:     *********************************************
 * 		    ** ED: Modified for userexitd              **
 *                  *********************************************
 *
 ***********************************************************************/
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include "userExitSample.h"


#ifndef DEFSOCKET
#define DEFSOCKET "unix:/var/run/userexitd.sock"
#endif

#define SOCKPATH_VAR "USEREXITD_ADDRESS"
#define MAXWAIT 3
#if 0
#define DEBUG
#endif
/**************************************
 *** Do not modify below this line. ***
 **************************************/
 
/*extern void adsmV3UserExit( void *anEvent );*/

/************
 *** Main ***
 ************/
static int sock=0;

static struct sockaddr_un t_addr_un;
static struct sockaddr_in t_addr_in;
static struct sockaddr *t_addr_p=NULL;
static size_t socksiz=0;

int main(int argc, char *argv[])
{
/* Do nothing, main() is never invoked, but stub is needed */

  exit(0);  /* For picky compilers */

} /* End of main() */


struct hostent *
gethostaddr (char *host,struct hostent* hostbuf)
{
  struct hostent *hp=NULL;
#ifdef AIX
  /* AIX  has a nice, fully reentrant libc! */
  return (gethostbyname(host));
#endif
#ifndef AIX

  size_t hstbuflen;
  char *tmphstbuf;
#ifndef SOLARIS
  int res;
#endif
  int herr;

  hstbuflen = BUFSIZ;
  /* Allocate buffer, remember to free it to avoid memory leakage.  */
  if (NULL==(tmphstbuf = malloc (hstbuflen))) {
    return NULL;
  }


#ifdef SOLARIS
  while (NULL==hp) {
    if (NULL!=(hp=gethostbyname_r (host, hostbuf, tmphstbuf, hstbuflen,&herr))) {
      return hp;
    }
    if (ERANGE==herr) {
      hstbuflen *= 2;
      tmphstbuf = realloc (tmphstbuf, hstbuflen);
      if (NULL==tmphstbuf) {
	return NULL;
      }
    } else {
      return NULL;
    }
  }
  return hp;
#endif
#ifdef __linux
  while ((res = gethostbyname_r (host, hostbuf, tmphstbuf, hstbuflen,
                                 &hp, &herr)) == ERANGE)
    {
      /* Enlarge the buffer.  */
      hstbuflen *= 2;
      tmphstbuf = realloc (tmphstbuf, hstbuflen);
      if (NULL==tmphstbuf) {
	return NULL;
      }
    }
  /*  Check for errors.  */
  if (res || hp == NULL)
    return NULL;
  return hp;
#endif
#endif /* ifndef AIX */
}

/******************************************************************
 * Procedure:  adsmV3UserExit
 * If the user-exit is specified on the server, a valid and
 * appropriate event will cause an elEventRecvData structure 
 * (see userExitSample.h) to be passed to a procedure named 
 * adsmV3UserExit that returns a void.
 *
 * INPUT :   A (void *) to the elEventRecvData structure
 * RETURNS:  Nothing
 ******************************************************************/

void adsmV3UserExit( void *anEvent )
{
/* Typecast the event data passed */
elEventRecvData *eventData = (elEventRecvData *)anEvent;
time_t st;

/**************************************
 *** Do not modify above this line. ***
 **************************************/
if (!eventData) {
	return;
}
if( ( eventData->eventNum == USEREXIT_END_EVENTNUM     ) ||
    ( eventData->eventNum == END_ALL_RECEIVER_EVENTNUM ) )
  {
   /* Server says to end this user-exit.  Perform any cleanup, *
    * but do NOT exit() !!!                                    */
    
   return;
  }
/* Field Access:  eventData->.... */
/* Your code here ... */

/* Be aware that certain function calls are process-wide and can cause
 * synchronization of all threads running under the TSM Server process!
 * Among these is the system() function call.  Use of this call can
 * cause the server process to hang and otherwise affect performance.
 * Also avoid any functions that are not thread-safe.  Consult your 
 * system's programming reference material for more information.
 */
 if (0==sock) {
#ifdef DEBUG
   fprintf(stderr," userexitd: socket is not initialized\n");
#endif 
   return;
 }
   
   st=time(NULL);
  do {
	  if (-1== sendto(sock,(void*)anEvent,sizeof(struct evRdata),
			0,
/*			MSG_DONTWAIT|MSG_NOSIGNAL,*/
			t_addr_p,socksiz)) {
	  	if ((EAGAIN!=errno) && (EWOULDBLOCK!=errno)) {
#ifdef DEBUG
	  		perror("sendto");
#endif
			break;
#ifdef DEBUG
	  	} else {

			fprintf(stderr," RETRY! ");
#endif
		}
	  } else {
		  break;
	  }
	  if ((time(NULL)-st)>MAXWAIT) {
#ifdef DEBUG
		  fprintf(stderr," GIVE UP! ");
#endif
		  break;
	  }
  } while(1);
return; /* For picky compilers */
} /* End of adsmV3UserExit() */


void _init(void) {
  char *spath=DEFSOCKET;
  struct hostent h,*hp;
  
  int i;
  fprintf(stderr,"\nuserexit: Initializing\n");
  if (getenv(SOCKPATH_VAR)) {
    spath=strdup(getenv(SOCKPATH_VAR));
    if (NULL==spath) {
      fprintf(stderr,"\nuserexit: strdup: Out Of Memory\n");
      sock=0;
      return;
    }
  }
  fprintf(stderr,"userexit: messages will go to %s\n",spath);
  if (!sock) {
      if (!strncmp(spath,"unix:",5)) {
	t_addr_un.sun_family=AF_UNIX;
	t_addr_p=(struct sockaddr*)&t_addr_un;
	socksiz=sizeof(t_addr_un);
	if (sizeof(t_addr_un.sun_path)<=(strlen(spath)-5)) {
	  fprintf(stderr,"userexit: ERROR: socket path '%s' is too long, userexit disabled!\n",spath+5);
	  sock=0;
	  return;
	}
	strcpy(t_addr_un.sun_path,spath+5);
	sock = socket(PF_UNIX, SOCK_DGRAM, 0); 
      } else if (!strncmp(spath,"udp:",4)) {
	t_addr_in.sin_family=AF_INET;
	t_addr_p=(struct sockaddr*)&t_addr_in;
	socksiz=sizeof(t_addr_in);
	for(i=4;(i<strlen(spath)) && (spath[i]!=':') ;i++);
	if (spath[i]==0) {
	  fprintf(stderr,"userexit: ERROR: incorrect address: '%s', userexit disabled!\n",spath);
	  sock=0;
	  return;
	}
	spath[i]=0;
	i++;
#ifdef DEBUG
	fprintf(stderr,"userexit: addr='%s' port='%s'\n",spath+4,spath+i);
#endif
	hp=gethostaddr(spath+4,&h);
	if (NULL==hp) {
	  if (!inet_aton(spath+4,&t_addr_in.sin_addr)) {
	    fprintf(stderr,"userexit: ERROR: invalid host name or address '%s'\n",spath+4);
	    sock=0;
	    return;
	  }
	} else {
	  memcpy(&t_addr_in.sin_addr,
		 hp->h_addr_list[0],
		 sizeof(t_addr_in.sin_addr));
	}
#ifdef DEBUG
	fprintf(stderr,"userexit: ip='%s'\n",inet_ntoa(t_addr_in.sin_addr));
#endif
	t_addr_in.sin_port=htons(atoi(spath+i));
	sock=socket(PF_INET,SOCK_DGRAM,0);
      } else {
	fprintf(stderr,"userexit: ERROR: incorrect address: '%s', userexit disabled!\n",spath);
	sock=0;
	return;
      }
      if (sock==-1) {
	fprintf(stderr,"userexit: ERROR: socket call failed!");
	sock=0;
	return;
      } 
      if (-1==fcntl(sock,F_SETFL,O_NONBLOCK)) {
	fprintf(stderr,"userexitd: ERROR: fcntl failed!");
	sock=0;
	return;
      }
  }
  fprintf(stderr,"userexit: initialized\n");
}

void  _fini(void) {
	fprintf(stderr,"\nuserexitd: unloading user exit\n");
	if (sock) {
	  close(sock);
		sock=0;
	}
}

