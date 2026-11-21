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

#ifdef EZRADIUS_HAS_CRYPTO
bool EZResponse::AddMSCHAP2Success(uint8_t ident, const std::string &authenticatorResponse)
{
    std::string v(1, (char)ident);
    v += authenticatorResponse;
    return v.size() <= 253 && ezutil::addVendor(m_Pck, D_VENDOR_MICROSOFT, MS_CHAP2_SUCCESS, v.data(), (uint16_t)v.size());
}

bool EZResponse::AddMSCHAPError(uint8_t ident, int errorCode, bool retryAllowed, const char *message)
{
    std::string v = EZMSCHAP::MakeErrorValue(ident, errorCode, retryAllowed, message);
    return v.size() <= 253 && ezutil::addVendor(m_Pck, D_VENDOR_MICROSOFT, MS_CHAP_ERROR, v.data(), (uint16_t)v.size());
}

bool EZResponse::AddMPPEKeys(const uint8_t sendKey[16], const uint8_t recvKey[16], uint32_t policy, uint32_t types)
{
    if(!sendKey || !recvKey)
        return false;
    memcpy(m_mppeSend, sendKey, 16);
    memcpy(m_mppeRecv, recvKey, 16);
    m_mppePolicy = policy;
    m_mppeTypes = types;
    m_hasMppe = true;
    return true;
}

bool EZResponse::AddMSCHAPv2Result(const EZMSCHAPv2Result &r, uint32_t mppePolicy, uint32_t mppeTypes)
{
    return AddMSCHAP2Success(r.ident, r.authenticatorResponse) && AddMPPEKeys(r.mppeSendKey, r.mppeRecvKey, mppePolicy, mppeTypes);
}

static bool addVendorNumber(RadiusPacket &pck, unsigned char type, uint32_t value)
{
    unsigned char be[4] = { (unsigned char)(value >> 24), (unsigned char)(value >> 16), (unsigned char)(value >> 8), (unsigned char)value };
    return ezutil::addVendor(pck, D_VENDOR_MICROSOFT, type, be, 4);
}
#endif

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

#ifdef EZRADIUS_HAS_CRYPTO
    if(m_hasMppe){
        const unsigned char *secret = nullptr;
        uint16_t secretLen = 0;
        if(ras->Secret.getSecret(secret, secretLen) != RC_SUCCESS)
            return false;
        const std::string s = EZMSCHAP::EncodeMppeKey(m_mppeSend, secret, secretLen, ClientIdentify->Authenticator());
        const std::string r = EZMSCHAP::EncodeMppeKey(m_mppeRecv, secret, secretLen, ClientIdentify->Authenticator());
        if(!ezutil::addVendor(m_Pck, D_VENDOR_MICROSOFT, MS_MPPE_SEND_KEY, s.data(), (uint16_t)s.size())
           || !ezutil::addVendor(m_Pck, D_VENDOR_MICROSOFT, MS_MPPE_RECV_KEY, r.data(), (uint16_t)r.size()))
            return false;
        if(m_mppePolicy && !addVendorNumber(m_Pck, MS_MPPE_ENCRYPTION_POLICY, m_mppePolicy))
            return false;
        if(m_mppeTypes && !addVendorNumber(m_Pck, MS_MPPE_ENCRYPTION_TYPES, m_mppeTypes))
            return false;
        m_hasMppe = false;      // a second Send() must not add the keys twice
    }
#endif

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
