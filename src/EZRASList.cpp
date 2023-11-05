#include "EZRASList.h"
#include <Wrench/log.h>
#include <arpa/inet.h>
using namespace std;


RASItem::RASItem()
{

}

RASItem::RASItem(const char *secret, uint32_t RASIP)
{
    IP = RASIP;
    Secret.setSecret(secret, strlen(secret));
}

void EZRASList::Init(int maximum)
{
    if(m_pList == nullptr){
        m_pList = new RASItem*[maximum+1];
        m_MaximumCount = maximum;

        for(uint32_t i = 0; i < m_MaximumCount; i++){
            m_pList[i] = nullptr;
        }
    }
}

void EZRASList::MutexLock()
{
    pthread_mutex_lock(&m_Mutex);
}

void EZRASList::MutexUnLock()
{
     pthread_mutex_unlock(&m_Mutex);
}

int EZRASList::GetAFree()
{
     for(uint32_t i = 0; i < m_MaximumCount;i++){
        if(m_pList[i] == nullptr){
            return i;
        }
     }
     return -1;
}

int EZRASList::GetItemByIP(uint32_t IPAddress)
{
     for(uint32_t i = 0; i < m_MaximumCount;i++){
        if(m_pList[i] != nullptr){
            if(m_pList[i]->IP == IPAddress){
                return i;
                break;
            }
        }
     }
     return ISINVALID;
}

EZRASList::EZRASList()
{
    m_pList = nullptr;

    //inition mutex
    if (pthread_mutex_init(&m_Mutex, nullptr) != 0){
        DebugPrint("pthread_mutex_init failed");
        return;
    }
    Init(512);
}

bool EZRASList::AddRAS(const char *Secret, const char* IPAddress)
{
    bool ret = false;
    MutexLock();

    // check ip exist
    int index = GetItemByIP(inet_addr(IPAddress));

    //if not exist continue
    if(index == ISINVALID){
        index = GetAFree();
        if(index != ISINVALID){
            //create RAS item
            RASItem *pRAS = new RASItem(Secret, inet_addr(IPAddress));

            //add RAS pointer to list
            m_pList[index] = pRAS;

            ret = true;
            m_Count ++;
        }
    }

    MutexUnLock();
    return ret;
}

 RASItem *EZRASList::GetRASByIP(uint32_t IPAddress)
{
    // search for an item by its IP
    MutexLock();
    RASItem * ret = nullptr;
    int index = GetItemByIP(IPAddress);
    if(index != ISINVALID){
        ret = m_pList[index];
    }
    MutexUnLock();
    return ret;
}

bool EZRASList::removeRASByIP(uint32_t IPAddress)
{
    bool ret = false;
    MutexLock();
    int index = GetItemByIP(IPAddress);
    if(index != ISINVALID){
        delete m_pList[index];
        m_pList[index] = nullptr;
    }
    MutexUnLock();
    return ret;
}




