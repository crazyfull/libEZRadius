#include "EZResponse.h"
#include "EZRadiusClientIdentify.h"
#include "EZAttrUtil.h"
#include "EZDedup.h"
#include "clsUDPSocket.h"

bool EZResponse::AddAttribute(RADIUSAttribute AttType, const char *value)
{
    if(AttType == D_ATTR_USER_PASSWORD || AttType == D_ATTR_CHAP_PASSWORD || AttType == D_ATTR_MESSAGE_AUTHENTICATOR)
        return false;
    return ezutil::addString(m_Pck, AttType, value);
}

bool EZResponse::AddAttribute(RADIUSAttribute AttType, uint32_t value)
{
    if(AttType == D_ATTR_USER_PASSWORD || AttType == D_ATTR_CHAP_PASSWORD || AttType == D_ATTR_MESSAGE_AUTHENTICATOR)
        return false;
    return ezutil::addNumber(m_Pck, AttType, value);
}

bool EZResponse::AddVendorAttribute(uint32_t vendorId, unsigned char vendorType, const void *data, uint16_t length)
{
    return ezutil::addVendor(m_Pck, vendorId, vendorType, data, length);
}

bool EZResponse::AddVendorAttribute(uint32_t vendorId, unsigned char vendorType, const char *text)
{
    if(!text)
        return false;
    size_t len = strnlen(text, 256);
    if(len > 255)
        return false;
    return ezutil::addVendor(m_Pck, vendorId, vendorType, text, (uint16_t)len);
}

bool EZResponse::Send(RADIUSPacketTypeCodes code, EZRadiusClientIdentify *ClientIdentify)
{
    if(!ClientIdentify || !ClientIdentify->Socket() || !ClientIdentify->RAS())
        return false;

    // keeps the RAS (and its secret) alive even if it is removed from the list meanwhile
    std::shared_ptr<RASItem> ras = ClientIdentify->RAS();

    m_Pck.setCode((unsigned char)code);
    m_Pck.setID(ClientIdentify->ID());
    m_Pck.setSecret(&ras->Secret);
    // the authenticator field holds the Request Authenticator until the response authenticator is calculated
    m_Pck.setAuthenticator(ClientIdentify->Authenticator());

    // Proxy-State attributes of the request must be copied unmodified and in order (RFC 2865 section 5.33)
    for(const std::string &ps : ClientIdentify->ProxyStates()){
        RadiusAttribute attr;
        if(ps.size() > D_ATTR_MAX_VALUE_LENGTH || m_Pck.addAttribute(D_ATTR_PROXY_STATE, attr) != RC_SUCCESS
           || attr.setString(ps.data(), (uint16_t)ps.size()) != RC_SUCCESS)
            return false;
    }

    const bool accessResponse = (code == ACCESS_ACCEPT || code == ACCESS_REJECT || code == ACCESS_CHALLENGE);
    if(accessResponse && ClientIdentify->RequestHadMessageAuthenticator()){
        if(!m_Pck.addMessageAuthenticator() || !m_Pck.signMessageAuthenticator())
            return false;
    }

    if(!m_Pck.responseAuthenticator())
        return false;

    if(!ClientIdentify->Socket()->sendTo(m_Pck.getRawData(), m_Pck.getLength(), ClientIdentify->Peer(), ClientIdentify->PeerLen()))
        return false;

    // remember the answer: a retransmitted request gets the same answer without being processed again
    if(ClientIdentify->dedup())
        ClientIdentify->dedup()->storeResponse(ClientIdentify->dedupKey(), m_Pck.getRawData(), m_Pck.getLength());
    return true;
}
