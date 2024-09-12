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

static bool          g_pstack = false;
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
        ber_print( ber->ber_ptr, ber->ber_end - ber->ber_ptr );
    }
}

/* Function definations */

extern "C"
{
    void sighdl_handler(int p_signum)
    {
        // Read signal number
        switch (p_signum)
        {

            //case SIGTRAP    :
            case SIGABRT    :
            case SIGBUS     :
            case SIGSEGV    :
                //case SIGILL     :
                //case SIGXCPU    :
                //case SIGXFSZ    :
                //case SIGFPE     :
                //case SIGSYS     :
            {

                char buff[300]={'P','c','d','i','e','d','\0'};
                struct timeval curr_time = {};
                gettimeofday(&curr_time, 0);
                syslog(LOG_USER | LOG_ALERT, buff);

                if (true == g_pstack)
                {
                    system(g_command);
                }

                signal(p_signum, SIG_DFL);//instead of kill, we will restore default handling for signal,
                raise(p_signum);  //and reraise him again

            }
            break;

            default :
                syslog(LOG_USER | LOG_ALERT, "INVALID SIGNAL RECEIVED");
                break;
        }
    }
} //extern "C"

bool signalhandler_init(std::string logical_name)
{



    int              ret = 0;
    sigset_t         sig_set;
    sigset_t         sig_set_orig;
    sigset_t         sig_set_mask;
    struct sigaction sig_action;
    struct stat      stat_buf;

    memset(&stat_buf, 0, sizeof(stat_buf));   // Initialize file status buffer

    g_pid = getpid();                        // Get current pid


    // Ensure that the pstack utility exists
#ifdef __linux__
    ret = stat("/usr/bin/gstack", &stat_buf);
#else
    ret = stat("/usr/bin/pstack", &stat_buf);
#endif

    if (0 != ret)
    {
        // pstack utility does not exist
        cout<<"pstack/gstack utility not present at standard location /usr/bin";
        return false;
    }
    else
    {
        // pstack exists
        g_pstack = true; // Indicate pstack utility exists

#ifdef __linux__
        snprintf(g_command, sizeof(g_command), "%s %d > /TspCore/%s.%d.pstack",
                 "/usr/bin/gstack", g_pid, logical_name.c_str(), g_pid);
#else
        snprintf(g_command, sizeof(g_command), "%s %d > /TspCore/%s.%d.pstack",
                 "/usr/bin/pstack", g_pid, logical_name.c_str(), g_pid);
#endif
    }

    // Block all possible signals while installing handlers
    memset(&sig_action, 0, sizeof(sig_action)); // Initialize signal set
    memset(&g_count, 0, sizeof(g_count));     // Initialize signal count

    sigfillset(&sig_set);                     // Include all signals for blocking
    sigemptyset(&sig_set_orig);               // Initialize sig set to contain original signal mask
    pthread_sigmask(SIG_SETMASK, &sig_set, &sig_set_orig); // Block all signals

    //Initialize mask of signal set to use
    sigemptyset(&sig_set_mask);

    //sigaddset(&sig_set_mask,SIGTRAP);
    //sigaddset(&sig_set_mask,SIGILL);    // 4 - Illegal instruction.
    sigaddset(&sig_set_mask, SIGABRT);  // 6 - Process abort signal.
    sigaddset(&sig_set_mask, SIGBUS);   // 7 - Access to an undefined portion of a memory object
    //sigaddset(&sig_set_mask,SIGFPE);    // 8 - Erroneous arithmetic operation.
    sigaddset(&sig_set_mask, SIGSEGV);  // 11 - address not mapped to object
    //sigaddset(&sig_set_mask,SIGXCPU);   // 24 - CPU time limit exceeded.
    //sigaddset(&sig_set_mask,SIGXFSZ);   // 25 - File size limit exceeded.
    //sigaddset(&sig_set_mask,SIGSYS);    // 31 - Bad system call.

    // Install signal handler
    sig_action.sa_flags = 0;               // No flags set
    sigfillset(&sig_action.sa_mask);       // All set of signals to be blocked during execution of signal-catching function
    sig_action.sa_handler = sighdl_handler; // Set signal handler

    // Loop over all possible signals
    for (int sig_no = 0; sig_no < SIGMAX; sig_no++)
    {
        // Install handler for each signal
        if (sigismember(&sig_set_mask, sig_no))
        {
            // Add the signal handler
            cout<<"Adding signal:" << sig_no << " to handler list";
            sigaction(sig_no, &sig_action, NULL);
        }
    }

    // Restore original mask
    pthread_sigmask(SIG_SETMASK, &sig_set_orig, NULL);

    return (true);
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

/* Function for setting an LDAP error. */
static void
set_ld_error(int err, char* matched, char* errmsg, void* dummy)
{
    struct ldap_error* le;
    le = (ldap_error*)pthread_getspecific(key);
    if (le == NULL)
    {
      return ;
    }
    le->le_errno = err;
    if (le->le_matched != NULL)
    {
        ldap_memfree(le->le_matched);
    }
    le->le_matched = matched;
    if (le->le_errmsg != NULL)
    {
        ldap_memfree(le->le_errmsg);
    }
    le->le_errmsg = errmsg;
}

/* Function for getting an LDAP error. */
static int
get_ld_error(char** matched, char** errmsg, void* dummy)
{
    cout<<"Here"<<__LINE__<<endl;
    struct ldap_error* le;
        cout<<"Here"<<__LINE__<<endl;

    le = (ldap_error*)pthread_getspecific(key);
        cout<<"Here"<<__LINE__<<endl;

    if (le == NULL)
    {
        cout<<"Here"<<__LINE__<<endl;

      return 1;
    }
    if (matched != NULL)
    {
        cout<<"Here"<<__LINE__<<endl;

        *matched = le->le_matched;
    }
    if (errmsg != NULL)
    {
        cout<<"Here"<<__LINE__<<endl;

        *errmsg = le->le_errmsg;
    }
        cout<<"Here"<<__LINE__<<endl;

    return (le->le_errno);
}

/* Function for setting errno. */
static void
set_errno(int err)
{
    errno = err;
}

/* Function for getting errno. */
static int
get_errno(void)
{
    return (errno);
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
                        cout << endl << "Response::(" << "msgId" << "," << msgid<< ")" << endl;
                        //ldap_msgfree(res);
                        //res = 0;
                    }
                    else
                    {
                        cout << endl << "Response::(" << "msgId" << "," << msgid<< ")" << endl;
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

    global_ber_callback = my_ber_callback;

    signalhandler_init("LdapClient");
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


    /* Set the function pointers for dealing with mutexes
     and error information. */
    memset(&tfns, '\0', sizeof(struct ldap_thread_fns));
    tfns.ltf_mutex_alloc = (void* (*)(void)) my_mutex_alloc;
    tfns.ltf_mutex_free = (void (*)(void*)) my_mutex_free;
    tfns.ltf_mutex_lock = (int (*)(void*)) pthread_mutex_lock;
    tfns.ltf_mutex_unlock = (int (*)(void*)) pthread_mutex_unlock;
    tfns.ltf_get_errno = get_errno;
    tfns.ltf_set_errno = set_errno;
    tfns.ltf_get_lderrno = get_ld_error;
    tfns.ltf_set_lderrno = set_ld_error;
    tfns.ltf_lderrno_arg = NULL;

    /* Set up this session to use those function pointers. */
    rc = ldap_set_option(ld, LDAP_OPT_THREAD_FN_PTRS, (void*) &tfns);
    if (rc < 0)
    {
        fprintf(stderr, "ldap_set_option (LDAP_OPT_THREAD_FN_PTRS): %s\n", ldap_err2string(rc));
        ldap_unbind(ld);
        ld = 0;
        exit(1);
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
                //continue;

            }
            else
            {
                cout << endl << "Request::(" << "msgid" << "," << msgid << ")" << endl;
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
