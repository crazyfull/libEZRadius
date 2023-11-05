#ifndef EZRASLIST_H
#define EZRASLIST_H
#include "RadiusSecret.h"
#include <cstdint>
#include <netinet/in.h>
#include <string>
#include <unordered_set>

struct RASItem{
    RadiusSecret Secret;
    in_addr_t IP;

    RASItem();
    RASItem(const char* secret, uint32_t RASIP);

};

class EZRASList
{
    RASItem **m_pList;
    pthread_mutex_t m_Mutex;
    uint32_t m_Count;
    uint32_t m_MaximumCount;

private:
    void Init(int maximum);
    void MutexLock();
    void MutexUnLock();
    int GetAFree();
    int GetItemByIP(uint32_t IPAddress);

public:
    EZRASList();
    bool AddRAS(const char*Secret, const char *IPAddress);
    RASItem *GetRASByIP(uint32_t IPAddress);
    bool removeRASByIP(uint32_t IPAddress);
};

#endif // EZRASLIST_H
