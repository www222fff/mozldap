#include <stdio.h>
#include <malloc.h>
#include <errno.h>
#include <pthread.h>
#include <ldap.h>
#include <ldappr.h>
#include<string.h>
#include<iostream>
#include<stdlib.h>
#include<unistd.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <syslog.h>

#include <lber.h> 
#include "lber-int.h"

#include<map>
/* Authentication and search information. */
#define NAME         "gn=John+sn=Doe,ou=people,dc=example,dc=org"
#define PASSWORD     "terces"
#define BASEDN "dc=example,dc=org"
#define SCOPE        LDAP_SCOPE_SUBTREE
#define FILTER       "(objectclass=*)"

#ifdef __linux__
#define SIGMAX       31
#else
#define SIGMAX       SIGLOST
#endif


static int          g_pid = 0;
static unsigned int g_count[SIGMAX];
static char         g_command[1024];

LDAP*    ld;

pthread_key_t  key;
pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

using namespace std;

//dannyaw
#define BPLEN	48
ber_callback_t global_ber_callback = NULL;

void ber_print( char *data, int len )
{
    static char	hexdig[] = "0123456789abcdef";
    char	out[ BPLEN ];
    int		i = 0;

    memset( out, 0, BPLEN );
    for ( ;; ) {
        if ( len < 1 ) {
            char msg[BPLEN + 80];
            sprintf( msg, "\t%s\n", ( i == 0 ) ? "(end)" : out );
            cout << msg << endl;
            break;
        }


        out[ i ] = hexdig[ ( *data & 0xf0 ) >> 4 ];
        out[ i+1 ] = hexdig[ *data & 0x0f ];

        i += 2;
        len--;
        data++;

        if ( i > BPLEN - 2 ) {
            char msg[BPLEN + 80];
            sprintf( msg, "\t%s\n", out );
            cout << msg << endl;
            memset( out, 0, BPLEN );
            i = 0;
            continue;
        }
        out[ i++ ] = ' ';
    }
}

void my_ber_callback(BerElement *ber, int is_request) {	
    char msg[128];

    if (is_request == 1)
    {
        sprintf( msg, "ldap request ber_dump: buf 0x%p, ptr 0x%p, rwptr 0x%p, end 0x%p\n",
	    ber->ber_buf, ber->ber_ptr, ber->ber_rwptr, ber->ber_end );
        cout << msg << endl;
        ber_print( ber->ber_buf, ber->ber_ptr - ber->ber_buf );
    }
    else
    {
        sprintf( msg, "ldap resposne ber_dump: buf 0x%p, ptr 0x%p, rwptr 0x%p, end 0x%p\n",
	    ber->ber_buf, ber->ber_ptr, ber->ber_rwptr, ber->ber_end );
        cout << msg << endl;
        ber_print( ber->ber_ptr, ber->ber_end - ber->ber_ptr );  //for response need add prefix 30 len!!!
    }
}


/* Function for allocating a mutex. */
static void*
my_mutex_alloc(void)
{
    pthread_mutex_t*  mutexp;
    if ((mutexp = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t))) != NULL)
    {
        pthread_mutex_init(mutexp, NULL);
    }
    return (mutexp);
}

/* Function for freeing a mutex. */
static void
my_mutex_free(void* mutexp)
{
    pthread_mutex_destroy((pthread_mutex_t*) mutexp);
    free(mutexp);
}


/* Error structure. */
struct ldap_error
{
    int  le_errno;
    char*  le_matched;
    char*  le_errmsg;
};

/* Function to set up thread-specific data. */
static void
tsd_setup()
{
    void*  tsd;
    tsd = pthread_getspecific(key);
    if (tsd != NULL)
    {
        fprintf(stderr, "tsd non-null!\n");
        pthread_exit(NULL);
    }
    tsd = (void*) calloc(1, sizeof(struct ldap_error));
    pthread_setspecific(key, tsd);
}


static void*
search_thread(void* id)
{
    LDAPMessage*  res;
    void*    tsd;
    timeval  t;
    t.tv_sec = t.tv_usec = 2L;

    printf("Starting search_thread %c.\n", *(char*)id);
    free(id);
    tsd_setup();

    for (;;)
    {

         LDAPMessage*  res;
         int    rc, msgid= LDAP_RES_ANY;

            rc = ldap_result(ld, msgid, 1, &t, &res);
            switch (rc)
            {
                case -1:
                    cout << " An error occurred" << endl;
                    //rc = ldap_get_lderrno(ld, NULL, NULL);
                    //fprintf(stderr, "ldap_result: %s\n", ldap_err2string(rc));
                    //ldap_unbind(ld);
                    //ld = 0;
                case 0:
                    break;
             
                default:
                    if (0 != res)
                    {
                        msgid = ldap_msgid(res);
                        cout << endl << "Above Response is for::(" << "msgId" << "," << msgid<< ")" << endl;
                        //ldap_msgfree(res);
                        //res = 0;
                    }
                    else
                    {
                        cout << endl << "Above Response is for::(" << "msgId" << "," << msgid<< ")" << endl;
                    }

                    if(msgid % 2 == 0)   //simulate FF change testing, only print even msgid.
                    {
                        global_ber_callback = NULL;    
                    }
                    else
                    {
                        global_ber_callback = my_ber_callback;
                    }
                    break;
            }
    }
}



int main()
{
    pthread_attr_t  attr;
    pthread_t  search_tid;
    void*    status;
    struct ldap_thread_fns  tfns;
    int rc;

    int    i , parse_rc, msgid, finished;


    /* Create a key. */
    if (pthread_key_create(&key, free) != 0)
    {
        perror("pthread_key_create");
    }
    tsd_setup();

    /* Initialize the LDAP session. */
    if ((ld = prldap_init("127.0.0.1", 16611,1)) == NULL)
    {
        perror("ldap_init");
        exit(1);
    }

     cout << endl << "LDAP Handle is "<<ld << endl;
    int version = LDAP_VERSION3;
    if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version) != LDAP_SUCCESS)
    {
        rc = ldap_get_lderrno(ld, NULL, NULL);
        fprintf(stderr, "ldap_set_option: %s\n", ldap_err2string(rc));
        ldap_unbind(ld);
        ld = 0;

    }
    int deref = LDAP_DEREF_ALWAYS;
    if (ldap_set_option(ld, LDAP_OPT_DEREF, &deref) != LDAP_SUCCESS)
    {
        rc = ldap_get_lderrno(ld, NULL, NULL);
        fprintf(stderr, "ldap_set_option: %s\n", ldap_err2string(rc));
        ldap_unbind(ld);
        ld = 0;

    }
    int timeout = 2 * 1000;
    if (ldap_set_option(ld, LDAP_X_OPT_CONNECT_TIMEOUT, &timeout) != LDAP_SUCCESS)
    {
        rc = ldap_get_lderrno(ld, NULL, NULL);
        fprintf(stderr, "ldap_set_option: %s\n", ldap_err2string(rc));
        ldap_unbind(ld);
        ld = 0;
    }
    int timelimit = 500;
    if (ldap_set_option(ld, LDAP_OPT_TIMELIMIT, &timelimit) != LDAP_SUCCESS)
    {
        rc = ldap_get_lderrno(ld, NULL, NULL);
        fprintf(stderr, "ldap_set_option: %s\n", ldap_err2string(rc));
        ldap_unbind(ld);
        ld = 0;
    }


    /* Attempt to bind to the server. */
    rc = ldap_simple_bind_s(ld, NAME, PASSWORD);
    if (rc != LDAP_SUCCESS)
    {
        fprintf(stderr, "ldap_simple_bind_s: %s\n", ldap_err2string(rc));
        exit(1);
    }

    /* Initialize the attribute. */
    if (pthread_attr_init(&attr) != 0)
    {
        perror("pthread_attr_init");
        exit(1);
    }

    /* Specify that the threads are joinable. */
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    /* Create seven threads: one for adding, one for modifying,
     one for deleting, and four for searching. */
    char* id;
    id = (char*)malloc(1 * sizeof(char));
    *id = '1';
    if (pthread_create(&search_tid, &attr, search_thread, (void*)ld) != 0)
    {
        perror("pthread_create search_thread");
        exit(1);
    }

    timeval  t;
    t.tv_sec = t.tv_usec = 2L;


    // Query Generator
    for(;;)
    {
      
    	    if(0 != ld)
    	    {
            
                int rc = ldap_search_ext( ld, BASEDN, LDAP_SCOPE_BASE, FILTER, 0, 0, 0, 0, &t, LDAP_NO_LIMIT, &msgid);
                if (rc != LDAP_SUCCESS)
                {
                    cout<<"---FAILED --- in ldap_search_ext-----"<<endl<<std::flush;

                }
                else
                {
                    cout << endl << "Above Request is for::(" << "msgid" << "," << msgid << ")" << endl;
                }       

           }
           else
           {           
                exit(1);
           }

           sleep(2);
        
     }  
    


    /* Wait until these threads exit. */
    pthread_join(search_tid, &status);

}
