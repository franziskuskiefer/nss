/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <string>

#include "pk11func.h"
#include "ssl.h"
#include "sslerr.h"
#include "sslproto.h"
#include "keyhi.h"
#include "prio.h"
#include "nss.h"
#include "prnetdb.h"
#include "prinit.h"

bool mSending = false;

static SECStatus
ownBadCertHandler(void *arg, PRFileDesc *socket)
{
    printf("We accept any cert!\n");
    return SECSuccess; /* everything's OK */
}

void
handshakeCallback(PRFileDesc *fd, void *client_data)
{
    printf("Handshake done!\n");
    mSending = true;
}

/* open TCP socket */
SECStatus openTCPSocket(PRFileDesc** s, PRBool non_blocking) {
    PRSocketOptionData opt;
    *s = PR_OpenTCPSocket(PR_AF_INET);
    if (*s == NULL) {
        printf("error creating socket\n");
        return SECFailure;
    }
    opt.option = PR_SockOpt_Nonblocking;
    opt.value.non_blocking = non_blocking;
    PR_SetSocketOption(*s, &opt);

    return SECSuccess;
}

/* set TLS options */
SECStatus initTLS(PRFileDesc** s, std::string hostName) {
    SECStatus rv = SECSuccess;
    char *dummy = nullptr;
    SSLVersionRange enabledVersions;
    enabledVersions.min = SSL_LIBRARY_VERSION_TLS_1_3;
    enabledVersions.max = SSL_LIBRARY_VERSION_TLS_1_3;

    *s = SSL_ImportFD(NULL, *s);
    if (*s == NULL) {
        printf("error importing socket\n");
        return SECFailure;
    }

    /* set url we connect to */
    SSL_SetURL(*s, hostName.c_str());

    /* set TLS options */
    rv = SSL_OptionSet(*s, SSL_SECURITY, 1);
    if (rv != SECSuccess) {
        printf("error enabling socket\n");
        return rv;
    }

    rv = SSL_OptionSet(*s, SSL_HANDSHAKE_AS_CLIENT, 1);
    if (rv != SECSuccess) {
        printf("error enabling client handshake\n");
        return rv;
    }

    rv = SSL_VersionRangeSet(*s, &enabledVersions);
    if (rv != SECSuccess) {
        printf("error setting SSL/TLS version range\n");
        return rv;
    }

    /* enable 0-RTT for TLS 1.3 */
    if (enabledVersions.max >= SSL_LIBRARY_VERSION_TLS_1_3) {
        rv = SSL_OptionSet(*s, SSL_ENABLE_0RTT_DATA, PR_TRUE);
        if (rv != SECSuccess) {
            printf("error enabling 0RTT\n");
            return rv;
        }
    }

    /* disable SSL socket locking */
    rv = SSL_OptionSet(*s, SSL_NO_LOCKS, PR_TRUE);
    if (rv != SECSuccess) {
        printf("error disabling SSL socket locking\n");
        return rv;
    }

    /* enable Session Ticket extension. */
    rv = SSL_OptionSet(*s, SSL_ENABLE_SESSION_TICKETS, PR_TRUE);
    if (rv != SECSuccess) {
        printf("error enabling session tickets\n");
        return rv;
    }

    /* make sure caching is enabled */
    rv = SSL_OptionSet(*s, SSL_NO_CACHE, PR_FALSE);
    if (rv != SECSuccess) {
        printf("error disabling cache\n");
        return rv;
    }

    /* we don't care about cert validity in this test */
    SSL_BadCertHook(*s, ownBadCertHandler, NULL);

    /* register handshake callback */
    SSL_HandshakeCallback(*s, handshakeCallback, dummy);

    return SECSuccess;
}

/* start TLS connection */
SECStatus startConnection(PRFileDesc** s, std::string hostIP, PRInt32 port) {
    PRNetAddr addr;

    PR_StringToNetAddr(hostIP.c_str(), &addr);
    addr.inet.port = PR_htons(port);
    if (PR_Connect(*s, &addr, PR_INTERVAL_NO_TIMEOUT) != PR_SUCCESS) {
        int32_t err = PR_GetError();
        printf("PR_Connect failed: %d\n", err);
    }
    printf("PR_Connect returned\n");
    SECStatus rv = SSL_ForceHandshake(*s);
    if (rv != SECSuccess) {
        int32_t err = PR_GetError();
        printf("SSL_ForceHandshake failed: %d\n", err);
        return SECFailure;
    }
    printf("SSL_ForceHandshake returned\n");

    return SECSuccess;
}

SECStatus readResponse(PRFileDesc** s) {
    PRPollDesc poller;
    poller.fd = *s;
    poller.in_flags = PR_POLL_EXCEPT | PR_POLL_READ;
    poller.out_flags = 0;
    printf("polling for server response ...\n");
    if (PR_Poll(&poller, 1, PR_INTERVAL_NO_TIMEOUT) <= 0) {
        printf("selecting socket for polling failed\n");
        return SECFailure;
    }
    printf("polling returned!\n");

    /* Read the server response */
    if ((poller.out_flags & PR_POLL_READ) ||
        (poller.out_flags & PR_POLL_ERR)) {
        char buf[4000];
        int nb = PR_Recv(poller.fd, buf, sizeof(buf), 0, PR_INTERVAL_NO_TIMEOUT);
        printf("Read from server %d bytes\n", nb);
        /* we expect nb = -1 here for the handshake */
        if (nb == 0) {
            /* server response was empty, let's bail */
            printf("empty server response\n");
            return SECFailure;
        }
        if (nb >= 0) {
            buf[nb - 1] = '\0';
            printf(" <<< server says:\n%s\n", buf);
        }
    }

    return SECSuccess;
}

SECStatus start0RTTConnection(PRFileDesc** s, std::string hostIP, PRInt32 port) {
    PRNetAddr addr;

    PR_StringToNetAddr(hostIP.c_str(), &addr);
    addr.inet.port = PR_htons(port);
    if (PR_Connect(*s, &addr, PR_INTERVAL_NO_TIMEOUT) != PR_SUCCESS) {
        int32_t err = PR_GetError();
        printf("PR_Connect failed: %d\n", err);
    }
    printf("PR_Connect returned\n");

    /* send 0-RTT data (NOTE: this also forces handshake) */
    const char *stringToSend = (std::string("0-RTT\n\n")).c_str();
    int nb = PR_Send(*s, stringToSend, strlen(stringToSend), 0, PR_INTERVAL_NO_TIMEOUT);
    if (nb < 0 || nb != strlen(stringToSend)) {
        printf("error sending '%s' to the server.\n", stringToSend);
        return SECFailure;
    }
    printf(" >>> sent 0-RTT data\n");

    return readResponse(s);
}

SECStatus sayHello(PRFileDesc** s) {
    const char *stringToSend = (std::string("hello\n\n")).c_str();

    PRInt32 sent = PR_Send(*s, stringToSend, strlen(stringToSend), 0, PR_INTERVAL_NO_TIMEOUT);
    if (sent < 0 || sent != (PRInt32)strlen(stringToSend)) {
        printf("error sending '%s' to the server.\n", stringToSend);
        return SECFailure;
    }
    printf(" >>> sent something!\n");

    return readResponse(s);
}

int
main(int argc, char **argv)
{
    SECStatus rv;
    std::string hostName = "franziskuskiefer.de"; //"localhost";
    std::string hostIP = "5.45.106.46"; //"127.0.0.1";
    PRInt32 port = 9913;
    PRFileDesc* s = nullptr;

    /* init DB */
    rv = NSS_NoDB_Init(NULL);
    if (rv != SECSuccess) {
        printf("failed to initialize NSS");
        return 1;
    }

    rv = openTCPSocket(&s, PR_FALSE);
    if (rv != SECSuccess) {
        printf("couldn't open TCP socket\n");
        return 1;
    }

    rv = initTLS(&s, hostName);
    if (rv != SECSuccess) {
        printf("couldn't initialise TLS\n");
        return 1;
    }

    rv = startConnection(&s, hostIP, port);
    if (rv != SECSuccess) {
        printf("couldn't initialise the connection\n");
        return 1;
    }

    rv = sayHello(&s);
    if (rv != SECSuccess) {
        printf("couldn't say hello\n");
        return 1;
    }

    /* reset connection */
    PR_Close(s);
    s = nullptr;
    mSending = false;
    printf(" === connection closed === \n");

    /* do it again */

    rv = openTCPSocket(&s, PR_FALSE);
    if (rv != SECSuccess) {
        printf("couldn't open TCP socket\n");
        return 1;
    }

    rv = initTLS(&s, hostName);
    if (rv != SECSuccess) {
        printf("couldn't initialise TLS\n");
        return 1;
    }

    rv = start0RTTConnection(&s, hostIP, port);
    if (rv != SECSuccess) {
        printf("couldn't send 0-RTT TLS handshake\n");
        return 1;
    }

    PR_Close(s);
    SSL_ClearSessionCache();
    if (NSS_Shutdown() != SECSuccess) {
        return 1;
    }

    PR_Cleanup();
    return 0;
}