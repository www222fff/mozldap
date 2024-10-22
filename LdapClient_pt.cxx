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
#include <ldap-int.h>
#include <ldappr.h>
#include <pprio.h>
#include <unordered_map>
#include <mutex>
#include <sys/socket.h>

#include<map>

/*danny test*/
/* Authentication and search information. */


#define NAME         "cn=sdfrun"
#define PASSWORD     "sdfrun1"
#define BASEDN       "subscriptionId=1,ds=hss,subdata=services,uid=BLT262025300570167,ds=SUBSCRIBER,o=DEFAULT,DC=C-NTDB"
#define SCOPE        LDAP_SCOPE_SUBTREE
#define FILTER       "(|(objectClass=hssSubscription)(objectClass=hssImpi)(objectClass=hssIrs)(objectClass=hssImpu))"
#define HOST          "10.9.230.65"

/*
#define NAME         "gn=John+sn=Doe,ou=people,dc=example,dc=org"
#define PASSWORD     "terces"
#define BASEDN "dc=example,dc=org"
#define SCOPE        LDAP_SCOPE_SUBTREE
#define FILTER       "(objectclass=*)"
#define HOST          "127.0.0.1"
*/

#ifdef __linux__
#define SIGMAX       31
#else
#define SIGMAX       SIGLOST
#endif

LDAP*    ld;
using namespace std;


// Global map to store the request send time for each msgid
std::unordered_map<int, PRTime> requestTimes;
std::mutex requestTimesMutex; // Mutex to protect the map

static void* search_thread(void* id);

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <tps>" << std::endl;
        return 1;
    }

    // 将命令行参数转换为整数
    unsigned int sleepTime = 1000000 / std::atoi(argv[1]);


    pthread_attr_t  attr;
    pthread_t  search_tid;
    void*    status;
    struct ldap_thread_fns  tfns;
    int rc;

    int    i , parse_rc, msgid, finished;

    /* Initialize the LDAP session.  */
    if ((ld = prldap_init(HOST, 16611,1)) == NULL)
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
                msgid = 0;
                int rc = ldap_search_ext( ld, BASEDN, LDAP_SCOPE_BASE, FILTER, 0, 0, 0, 0, &t, LDAP_NO_LIMIT, &msgid);
                if (rc != LDAP_SUCCESS)
                {
                    cout<<"---FAILED --- in ldap_search_ext-----"<<endl<<std::flush;

                }
                else
                {                    
                    PRTime requestSendTime = PR_Now();
                    std::lock_guard<std::mutex> lock(requestTimesMutex);
                    requestTimes[msgid] = requestSendTime;
                    std::cout << "Search request send at: " << requestSendTime << " microseconds since epoch, msgid: " << msgid << std::endl;
                }       

           }
           else
           {           
                exit(1);
           } 

            usleep(sleepTime);
      
        
     }  


    /* Wait until these threads exit. */
    pthread_join(search_tid, &status);

}


static void*
search_thread(void* ld)
{
    LDAPMessage*  res;
    void*    tsd;
    timeval  t;
    t.tv_sec = t.tv_usec = 2L;
    
    for (;;)
    {

         LDAPMessage*  res;
         int    rc, msgid= LDAP_RES_ANY;

        PRTime searchResultTime1 = PR_Now();
        std::cout << "Search result begin at: " << searchResultTime1 << " microseconds since epoch" << std::endl;

            rc = ldap_result((LDAP*)ld, msgid, 1, &t, &res);
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

                    // Capture the time when the search result is received
                    PRTime searchResultTime = PR_Now();
                    std::cout << "Search result received at: " << searchResultTime << " microseconds since epoch, msgid: " << msgid << std::endl;

                    // Retrieve the request send time for this msgid
                    PRTime requestSendTime;
                    {  
                        std::lock_guard<std::mutex> lock(requestTimesMutex);                      
                        auto it = requestTimes.find(msgid);
                        if (it != requestTimes.end()) {
                            requestSendTime = it->second;
                            requestTimes.erase(it);
                        } else {
                            std::cout << "No send time found for msgid " << msgid << std::endl;
                            ldap_msgfree(res);
                            continue;
                        }
                    }

                    // Compare the two timestamps
                    PRTime timeDifference = searchResultTime - requestSendTime;
                    PRTime timeDifferenceMillis = timeDifference / 1000;
                    std::cout << "Time difference for msgid " << msgid << ": " << timeDifferenceMillis << " milliseconds" << std::endl;

                    ldap_msgfree(res);                   
                    
            }
    }
}


