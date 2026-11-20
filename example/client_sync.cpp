// Blocking client: no reactor needed. Send() returns when the answer (or the timeout) is there.
//   ./ezradius_client_sync <host> <secret> <user> <password> [mschapv2]
#include <cstdio>
#include <cstring>
#include "EZRadiusSyncClient.h"

int main(int argc, char **argv)
{
    EZClientSettings settings;
    settings.Host = argc > 1 ? argv[1] : "127.0.0.1";
    settings.Secret = argc > 2 ? argv[2] : "change-me";
    const char *user = argc > 3 ? argv[3] : "user";
    const char *pass = argc > 4 ? argv[4] : "pass";
    const bool mschap = argc > 5 && strcmp(argv[5], "mschapv2") == 0;
    settings.TimeOut = 1500;
    settings.RetryCount = 3;

    EZRadiusSyncClient client(settings);
    if(mschap){
#ifdef EZRADIUS_HAS_CRYPTO
        client.AddMSCHAPv2(user, pass);
#else
        fprintf(stderr, "built without BoringSSL: MS-CHAPv2 is not available\n");
        return 2;
#endif
    }else{
        client.AddAttribute(USER_NAME, user);
        client.AddAttribute(USER_PASSWORD, pass);
    }
    client.AddAttribute(NAS_IP_ADDRESS, "192.168.1.1");

    EZResult r = client.Send(C_ACCESS_REQUEST);       // blocks
    if(r != EZResult::OK){
        printf("no answer (result %d)\n", (int)r);
        return 1;
    }
    printf("%s\n", client.GetResponseTypeDescription());
    return client.GetResponseType() == ACCESS_ACCEPT ? 0 : 1;
}
