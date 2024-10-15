#include <stdio.h>
#include <malloc.h>
#include <errno.h>
#include <pthread.h>
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

#include <ldap.h>
#include <ldappr.h>
#include <pprio.h>

#include <sys/socket.h>

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

//dannyaw
extern "C" void ldap_tapping_callback(Sockbuf *sb, char *ber, int ber_len, int is_request, char* len_content, int len_content_len);

LDAP*    ld;
pthread_key_t  key;
using namespace std;


typedef struct lextiof_socket_private {
	PRFileDesc	*prsock_prfd;		/* associated NSPR file desc. */
	int		prsock_io_max_timeout;	/* in milliseconds */
	void		*prsock_appdata;	/* application specific data */
} PRLDAPIOSocketArg;

#define BPLEN	48  //max print chars per line!

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

void get_socket_info(Sockbuf* sb) {

    struct lber_x_ext_io_fns    extiofns;
    memset( &extiofns, 0, sizeof(extiofns));
    extiofns.lbextiofn_size = LBER_X_EXTIO_FNS_SIZE;
    if ( ber_sockbuf_get_option(sb, LBER_SOCKBUF_OPT_EXT_IO_FNS, (void *)&extiofns ) < 0 || NULL == extiofns.lbextiofn_socket_arg) {
        return;
    }

    PROsfd sockfd = PR_FileDesc2NativeHandle(extiofns.lbextiofn_socket_arg->prsock_prfd);
    std::cout << "socket id is " << sockfd << std::endl;

    struct sockaddr_in local_addr, remote_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);

    // Get local address
    if (getsockname(sockfd, (struct sockaddr *)&local_addr, &addr_len) == -1) {
        perror("getsockname failed");
        return;
    }

    // Get remote address
    if (getpeername(sockfd, (struct sockaddr *)&remote_addr, &addr_len) == -1) {
        perror("getpeername failed");
        return;
    }

    char local_ip[INET_ADDRSTRLEN];
    char remote_ip[INET_ADDRSTRLEN];
    
    // Convert IP addresses to string
    inet_ntop(AF_INET, &local_addr.sin_addr, local_ip, sizeof(local_ip));
    inet_ntop(AF_INET, &remote_addr.sin_addr, remote_ip, sizeof(remote_ip));

    cout << "Local IP: " << local_ip << ":" << ntohs(local_addr.sin_port) << endl;
    cout << "Rmote IP: " << remote_ip << ":" << ntohs(remote_addr.sin_port) << endl;

}


void ldap_tapping_callback(Sockbuf *sb, char *ber, int ber_len, int is_request, char* len_content, int len_content_len) {
    char msg[128];
    if (is_request == 1)
    {
        cout << endl << "Request is --------------->" <<  endl;
        ber_print( ber, ber_len);
    }
    else
    {
        cout << endl << "Response is <---------------" <<  endl;
        //add tag and len for response
        char tag = 0x30;
        string tag_data(1, tag);
        string len_data(len_content, len_content_len);
        string ber_data(ber, ber_len);
        string combined_data = tag_data + len_data + ber_data;

        ber_print(const_cast<char*>(combined_data.c_str()), combined_data.length());
    }

    get_socket_info(sb);
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
                    msgid = ldap_msgid(res);
                    /*while (res != NULL)
                    {
                        cout << "danny:ldap result begin" << endl;
                        ber_print( res->lm_ber->ber_buf, res->lm_ber->ber_end - res->lm_ber->ber_buf );
                        cout << "danny:ldap result end" << endl;
                        res = ldap_next_message(ld, res);
                    }*/
                    
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

    if (ldap_set_option(ld, LDAP_OPT_DUMP_BER_FN, (void*)ldap_tapping_callback) != LDAP_SUCCESS)
    {
        rc = ldap_get_lderrno(ld, NULL, NULL);
        cout << "danny error" << ldap_err2string(rc) << endl;;
        ldap_unbind(ld);
        ld = 0;
    }

    /*int level = 0xFFFFF;
    ldap_set_option(ld, LDAP_OPT_DEBUG_LEVEL, (void *) &level);*/
  
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
                    /*LDAPRequest	*lr;
                    for ( lr = ld->ld_requests; lr != NULL; lr = lr->lr_next ) {
                        if ( msgid == lr->lr_msgid ) {
                            break;
                        }
                    }
                    if ( lr != NULL ) {
                        cout << "danny:ldap search begin" << endl;
                        char msg[128];
                        sprintf( msg, "ldap search ber: buf 0x%p, ptr 0x%p, rwptr 0x%p, end 0x%p\n",
                        lr->lr_ber->ber_buf, lr->lr_ber->ber_ptr, lr->lr_ber->ber_rwptr, lr->lr_ber->ber_end );
                        cout << msg << endl;
                        ber_print( lr->lr_ber->ber_buf, lr->lr_ber->ber_end - lr->lr_ber->ber_buf );
                        cout << "danny:ldap search end" << endl;
                    }*/                    
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
