#include <iostream>
#include <Wrench/log.h>
#include "src/EZRadiusServer.h"
using namespace std;

EZRadiusServer m_EZRadiusServer;

int main()
{
/*
 * https://idblender.com/tools/test-radius#85a7e4a0-6dce-4f70-a1b0-fcc8a2cdb2be
     * radtest -t pap moji moji '2.176.229.202:1812' 0 123456
*/

    m_EZRadiusServer.setAuthenticationPort(1812);
    m_EZRadiusServer.setSecret("123456");
    m_EZRadiusServer.Start();

    //LOG_COLOR(Green, "Hiiii ");
    getchar();
    return 0;
}
