/*
 * This source file is part of the ace-radius library.  This code was
 * written by Alex Agranov in 2004-2009, and is covered by the BSD open source
 * license. Refer to the accompanying documentation for details on usage and
 * license.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _MSC_VER
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#endif
#include <string.h>
#include <stdio.h>
#include <strings.h>
#include <algorithm>

#include "RadiusPacket.h"
#include "RadiusSecret.h"

#include "Radius.h"
#include "md5.h"



// the following table must be synchronized with definition of Packet Codes in RadiusPacket.h file
static const char *PacketCodeDescription[] =
    {
        "unknown",                  // 0
        "Access-Request",           // 1
        "Access-Accept",            // 2
        "Access-Reject",            // 3
        "Accounting-Request",       // 4
        "Accounting-Response",      // 5
        "Accounting-Status",        // 6
        "Password-Request",         // 7
        "Password-Ack",             // 8
        "Password-Reject",          // 9
        "Accounting-Message",       // 10
        "Access-Challenge",         // 11
        "Status-Server",            // 12
        "Status-Client",            // 13
        "Reserved",                 // 14
        "Reserved",                 // 15
        "Reserved",                 // 16
        "Reserved",                 // 17
        "Reserved",                 // 18
        "Reserved",                 // 19
        "Reserved",                 // 20
        "Resource-Free-Request",    // 21
        "Resource-Free-Response",   // 22
        "Resource-Query-Request",   // 23
        "Resource-Query-Response",  // 24
        "Alternate-Resource-Reclaim-Request", // 25
        "NAS-Reboot-Request",       // 26
        "NAS-Reboot-Response",      // 27
        "Reserved",                 // 28
        "Reserved",                 // 29
        "Next-Passcode",            // 30
        "New-Pin",                  // 31
        "Terminate-Session",        // 32
        "Password-Expired",         // 33
        "Reserved",                 // 34
        "Reserved",                 // 35
        "Reserved",                 // 36
        "Reserved",                 // 37
        "Reserved",                 // 38
        "Reserved",                 // 39
        "Disconnect-Request",       // 40
        "Disconnect-ACK",           // 41
        "Disconnect-NAK",           // 42
        "CoA-Request",              // 43
        "CoA-ACK",                  // 44
        "CoA-NAK",                  // 45
};


// ---------------------------
// Constructor
// ---------------------------
RadiusPacket::RadiusPacket(unsigned char p_code) {
    init(p_code);
    randomAuthenticator();
}


// ---------------------------
// Constructor (packet received from the network)
// ---------------------------
RadiusPacket::RadiusPacket(const char *Data, int DataLength, unsigned char p_code)
{
    init(p_code);
    setRawData(Data, DataLength);
}

// ---------------------------
// Constructor
// ---------------------------
RadiusPacket::RadiusPacket(unsigned char p_code, RadiusPacket & p_request)
{
    init(p_code);
    setID(p_request.getID());
    m_secret = p_request.getSecret();
    setAuthenticator(p_request.getAuthenticator());
}


// ---------------------------
// Init packet
// ---------------------------
void RadiusPacket::init(unsigned char p_code)
{
    m_secret = NULL;
    m_valid = true;
    resetBody();
    setCode(p_code);
}

// ---------------------------
// Clear packet content (the secret is kept)
// ---------------------------
void RadiusPacket::resetBody(void)
{
    memset(m_data, 0, sizeof(m_data));
    memset(m_password, 0, sizeof(m_password));
    memset(m_oldPassword, 0, sizeof(m_oldPassword));
    m_passwordLength = 0;
    m_passwordOffset = 0;
    m_oldPasswordLength = 0;
    m_oldPasswordOffset = 0;
    setLength(D_RADIUS_PACKET_HEADER_LENGTH);
}


// ---------------------------
// Destructor
// ---------------------------
RadiusPacket::~RadiusPacket()
{
    // do not leave plain text passwords in freed memory
    explicit_bzero(m_password, sizeof(m_password));
    explicit_bzero(m_oldPassword, sizeof(m_oldPassword));
}

// ---------------------------
// Load a packet received from the network
// ---------------------------
bool RadiusPacket::setRawData(const char *Data, int DataLength)
{
    resetBody();
    m_valid = false;

    if (Data == NULL || DataLength < D_RADIUS_PACKET_HEADER_LENGTH || DataLength > D_RADIUS_PACKET_MAX_LENGTH)
        return false;

    // length from the packet header: must be inside the received data
    uint16_t l_netLength;
    memcpy(&l_netLength, Data + 2, sizeof(uint16_t));
    uint32_t l_length = ntohs(l_netLength);
    if (l_length < D_RADIUS_PACKET_HEADER_LENGTH || l_length > D_RADIUS_PACKET_MAX_LENGTH || l_length > (uint32_t)DataLength)
        return false;

    // octets beyond the length field are padding and must be ignored (RFC 2865, section 3)
    memcpy(m_data, Data, l_length);

    // every attribute must have a sane length and lie inside the packet
    uint32_t l_offset = D_RADIUS_PACKET_HEADER_LENGTH;
    while (l_offset < l_length)
    {
        if (l_offset + 2 > l_length)
            break;

        uint32_t l_attrLength = m_data[l_offset + 1];
        if (l_attrLength < 2 || l_offset + l_attrLength > l_length)
            break;

        l_offset += l_attrLength;
    }

    if (l_offset != l_length)
    {
        resetBody();
        return false;
    }

    m_valid = true;
    return true;
}


// ---------------------------
// Get packet code
// ---------------------------
unsigned char RadiusPacket::getCode(void)
{
    return m_data[0];
}


// ---------------------------
// Set packet code
// ---------------------------
void RadiusPacket::setCode(unsigned char p_code)
{
    m_data[0] = p_code;
}


// ---------------------------
// Get packet code description
// ---------------------------
const char * RadiusPacket::getCodeDescription(void)
{
    return getCodeDescription(getCode());
}

const char * RadiusPacket::getCodeDescription(unsigned char l_code )
{
    if (l_code > D_PACKET_MAX_KNOWN_CODE )
        return PacketCodeDescription[0];
    else
        return PacketCodeDescription[l_code];
}


// ---------------------------
// Get packet identificator
// ---------------------------
unsigned char RadiusPacket::getID(void)
{
    return m_data[1];
}


// ---------------------------
// Set packet identificator
// ---------------------------
void RadiusPacket::setID(unsigned char p_id)
{
    m_data[1] = p_id;
}


// ---------------------------
// Set random packet identifier
// ---------------------------
void RadiusPacket::randomID()
{
    unsigned char l_id = 0;
    if (!SecureRandom(&l_id, 1))
    {
        struct timeval l_time;
        gettimeofday(&l_time, NULL);
        l_id = (unsigned char)((l_time.tv_usec / 1000) & 0xFF);
    }
    m_data[1] = l_id;
}


// ---------------------------
// Set secret
// ---------------------------
void RadiusPacket::setSecret(RadiusSecret * p_secret)
{
    m_secret = p_secret;
}


// ---------------------------
// Get packet's length
// ---------------------------
uint16_t RadiusPacket::getLength(void)
{
    uint16_t l_length;
    memcpy(&l_length, m_data + 2, sizeof(uint16_t));
    l_length = ntohs(l_length);

    // never trust the length field further than the packet buffer
    if (l_length > D_RADIUS_PACKET_MAX_LENGTH)
        l_length = D_RADIUS_PACKET_MAX_LENGTH;
    return l_length;
}


// ---------------------------
// Set packet's length
// ---------------------------
void RadiusPacket::setLength(uint16_t p_length)
{
    uint16_t l_length = htons(p_length);
    memcpy(m_data + 2, &l_length, sizeof(uint16_t));
}


// ---------------------------
// Get packet authenticator
// ---------------------------
const unsigned char * RadiusPacket::getAuthenticator(void)
{
    return m_data + 4;
}


// ---------------------------
// Set packet authenticator
// ---------------------------
void RadiusPacket::setAuthenticator(const unsigned char * p_auth)
{
    memmove(m_data + 4, p_auth, D_AUTHENTICATOR_LENGTH);
}


// ---------------------------
// Get secret key associated with this packet
// ---------------------------
RadiusSecret * RadiusPacket::getSecret(void)
{
    return m_secret;
}


// ---------------------------
// secret to use: p_secret or the secret associated with the packet
// ---------------------------
bool RadiusPacket::resolveSecret(RadiusSecret * p_secret, const unsigned char * & p_data, uint16_t & p_length)
{
    RadiusSecret * l_secret = (p_secret != NULL) ? p_secret : m_secret;

    p_data = NULL;
    p_length = 0;
    if (l_secret == NULL)
        return false;

    return l_secret->getSecret(p_data, p_length) == RC_SUCCESS && p_length > 0;
}


// ---------------------------
// Generate a random Request Authenticator.
// RFC 2865: it must be unpredictable and unique over the lifetime of a secret,
// so the operating system CSPRNG is used.
// ---------------------------
void RadiusPacket::randomAuthenticator(void)
{
    if (SecureRandom(m_data + 4, D_AUTHENTICATOR_LENGTH))
        return;

    // CSPRNG is not available (should never happen): mix the weak sources
    char l_hash[256], *l_ptr = l_hash;
    gethostname(l_ptr, sizeof(l_hash)-50);
    l_ptr[sizeof(l_hash)-51] = 0;
    l_ptr += strlen(l_ptr);

    struct timeval  l_time;
    gettimeofday(&l_time, NULL);
    snprintf(l_ptr, 50, ":%lu:%lu:%d", (unsigned long)l_time.tv_sec, (unsigned long)l_time.tv_usec, (int)getpid());

    MD5Calc(m_data + 4, (const unsigned char *)l_hash, (uint32_t)strlen(l_hash));
}


// ---------------------------
// dump radius packet in readable text format to the STDOUT
// ---------------------------
void RadiusPacket::dump()
{
    int i;

    // first dump packet raw data in HEX format (getLength() never exceeds the buffer)
    uint16_t l_length = getLength();
    for (i=0; i<l_length; i++)
    {
        if (i%16 == 0)
            printf("\n");
        printf("%02x ", m_data[i]);
    }

    printf("\n\n");

    // dump packet code and code description
    printf(" 1  Code = %s (%u)\n", getCodeDescription(), getCode());
    
    // dump packet identifier
    printf(" 1  ID = %u\n", getID());
    
    // dump packet length
    printf(" 2  Length = %u\n", getLength());

    // dump request authenticator
    printf("16  Request Authenticator = ( ");

    const unsigned char * l_auth = getAuthenticator();
    for (i=0; i<D_AUTHENTICATOR_LENGTH; i++)
    {
        printf("%02x ", *l_auth++);
    }

    printf(")\n");

    
    RadiusAttribute l_attr;
    for (getFirstAttribute(l_attr);
         l_attr.isValid();
         getNextAttribute(l_attr))
    {
        l_attr.dump();
    }

    printf("\n");
}



// ---------------------------
// Get first attribute in the packet
// ---------------------------
int RadiusPacket::getFirstAttribute(RadiusAttribute & p_attr)
{
    if (getLength() <= D_RADIUS_PACKET_HEADER_LENGTH)
    {
        p_attr.init(this, 0);
        return RC_FAIL;
    }
    
    p_attr.init(this, D_RADIUS_PACKET_HEADER_LENGTH);
    if (!p_attr.isWellFormed())
    {
        p_attr.init(this, 0);
        return RC_FAIL;
    }
    return RC_SUCCESS;
}


// ---------------------------
// Get next attribute in the packet
// ---------------------------
int RadiusPacket::getNextAttribute(RadiusAttribute & p_attr)
{
    unsigned int l_offset = p_attr.getOffset(),
        l_length = p_attr.getLength();
    
    if ((l_length < 2) || (l_offset + l_length >= getLength()))
    {
        p_attr.init(this, 0);
        return RC_FAIL;
    }

    p_attr.init(this, l_offset + l_length);
    if (!p_attr.isWellFormed())
    {
        p_attr.init(this, 0);
        return RC_FAIL;
    }
    return RC_SUCCESS;
}


// ---------------------------
// Find specific attribute in the packet
// ---------------------------
int RadiusPacket::findAttribute(unsigned char p_attrType, RadiusAttribute & p_attr)
{
    for(getFirstAttribute(p_attr); p_attr.isValid(); getNextAttribute(p_attr))
    {
        if (p_attr.getType() == p_attrType)
            return RC_SUCCESS;
    }
    
    return RC_FAIL;
}



AttrValueTypes RadiusPacket::getAttributeType(uint8_t attrType){

    switch (attrType)
    {
    case D_ATTR_NAS_PORT:
    case D_ATTR_SERVICE_TYPE:
    case D_ATTR_FRAMED_PROTOCOL:
    case D_ATTR_FRAMED_ROUTING:
    case D_ATTR_FRAMED_MTU:
    case D_ATTR_FRAMED_COMPRESSION:
    case D_ATTR_LOGIN_SERVICE:
    case D_ATTR_LOGIN_TCP_PORT:
    case D_ATTR_FRAMED_IPX_NETWORK:
    case D_ATTR_SESSION_TIMEOUT:
    case D_ATTR_IDLE_TIMEOUT:
    case D_ATTR_TERMINATION_ACTION:
    case D_ATTR_FRAMED_APPLETALK_LINK:
    case D_ATTR_FRAMED_APPLETALK_NETWORK:
    case D_ATTR_NAS_PORT_TYPE:
    case D_ATTR_PORT_LIMIT:
    case D_ATTR_ACCT_STATUS_TYPE:
    case D_ATTR_ACCT_DELAY_TIME:
    case D_ATTR_ACCT_INPUT_OCTETS:
    case D_ATTR_ACCT_OUTPUT_OCTETS:
    case D_ATTR_ACCT_AUTHENTIC:
    case D_ATTR_ACCT_SESSION_TIME:
    case D_ATTR_ACCT_INPUT_PACKETS:
    case D_ATTR_ACCT_OUTPUT_PACKETS:
    case D_ATTR_ACCT_TERMINATE_CAUSE:
    case D_ATTR_ACCT_LINK_COUNT:
    case D_ATTR_ACCT_INPUT_GIGAWORDS:     // high 32 bits of Acct-Input-Octets (traffic > 4GB)
    case D_ATTR_ACCT_OUTPUT_GIGAWORDS:    // high 32 bits of Acct-Output-Octets
    case D_ATTR_EVENT_TIMESTAMP:
    case D_ATTR_EGRESS_VLANID:
    case D_ATTR_INGRESS_FILTERS:
    case D_ATTR_TUNNEL_TYPE:
    case D_ATTR_TUNNEL_MEDIUM_TYPE:
    case D_ATTR_ARAP_ZONE_ACCESS:
    case D_ATTR_ARAP_SECURITY:
    case D_ATTR_PASSWORD_RETRY:
    case D_ATTR_PROMPT:
    case D_ATTR_TUNNEL_PREFERENCE:
    case D_ATTR_ACCT_INTERIM_INTERVAL:
        return ATTR_TYPE_INTEGER;

    case D_ATTR_NAS_IP_ADDRESS:
    case D_ATTR_FRAMED_IP_ADDRESS:
    case D_ATTR_FRAMED_IP_NETMASK:
    case D_ATTR_LOGIN_IP_HOST:
        return ATTR_TYPE_IP_ADDRESS;

    case D_ATTR_USER_PASSWORD:
        return ATTR_TYPE_PASSWORD;

    case D_ATTR_CHAP_PASSWORD:
        return ATTR_TYPE_CHAP_PASSWORD;

    case D_ATTR_VENDOR_SPECIFIC:
        return ATTR_TYPE_VENDOR_SPECIFIC;

    default:
        return ATTR_TYPE_FORMAT_STRING;
    }
}


// decode one attribute into AttrValue
static AttrValue decodeAttribute(RadiusAttribute & p_attr)
{
    AttrValue value;
    value.ValueType = RadiusPacket::getAttributeType(p_attr.getType());

    switch (value.ValueType)
    {
    case ATTR_TYPE_PASSWORD:
    {
        //Get PAP Password (maximum 128 bytes)
        uint16_t pwlength = 0;
        char pw[D_USER_PASSWORD_MAX_LENGTH];
        if (p_attr.getUserPassword(pw, pwlength) == RC_SUCCESS)
        {
            value.strValue.assign(pw, pwlength);
            value.valid = true;
        }
        explicit_bzero(pw, sizeof(pw));
        break;
    }

    case ATTR_TYPE_IP_ADDRESS:
    {
        //Get IP-Address V4 Format
        if (p_attr.getLength() >= 6)
        {
            char buf[INET_ADDRSTRLEN];
            struct in_addr addr = p_attr.getIPAddress();
            if (inet_ntop(AF_INET, &addr, buf, sizeof(buf)))
            {
                value.strValue.assign(buf);
                value.valid = true;
            }
        }
        break;
    }

    case ATTR_TYPE_CHAP_PASSWORD:
    {
        const char * str = NULL;
        uint16_t len = 0;
        if (p_attr.getLength() >= 3 && p_attr.getChapString(str, len) == RC_SUCCESS)
        {
            value.intValue = p_attr.getChapIdentifier();
            value.strValue.assign(str, len);
            value.valid = true;
        }
        break;
    }

    case ATTR_TYPE_VENDOR_SPECIFIC:
    {
        const char * str = NULL;
        uint16_t len = 0;
        if (p_attr.getLength() >= 6 && p_attr.getVendorRawString(str, len) == RC_SUCCESS)
        {
            value.intValue = p_attr.getVendorId();
            value.strValue.assign(str, len);
            value.valid = true;
        }
        break;
    }

    case ATTR_TYPE_INTEGER:
        //Get Numbers (uint32)
        if (p_attr.getLength() >= 6)
        {
            value.intValue = p_attr.getNumber();
            value.valid = true;
        }
        break;

    case ATTR_TYPE_FORMAT_STRING:
    default:
    {
        //Get String
        uint16_t strValueLen = 0;
        const char *strValue = NULL;
        if (p_attr.getString(strValue, strValueLen) == RC_SUCCESS)
        {
            value.strValue.assign(strValue, strValueLen);
            value.valid = true;
        }
        break;
    }
    }

    return value;
}


AttrValue RadiusPacket::getAttribute(RADIUSAttribute attrType){

    RadiusAttribute l_attr;
    if (findAttribute(attrType, l_attr) == RC_SUCCESS)
        return decodeAttribute(l_attr);

    AttrValue value;
    value.ValueType = getAttributeType(attrType);
    return value;
}


std::vector<AttrValue> RadiusPacket::getAttributes(RADIUSAttribute attrType)
{
    std::vector<AttrValue> result;

    RadiusAttribute l_attr;
    for (getFirstAttribute(l_attr); l_attr.isValid(); getNextAttribute(l_attr))
    {
        if (l_attr.getType() == attrType)
            result.push_back(decodeAttribute(l_attr));
    }
    return result;
}


// ---------------------------
// Add new attribute to the packet
// ---------------------------
int RadiusPacket::addAttribute(unsigned char p_attrType, RadiusAttribute & p_attr)
{
    uint16_t l_length = getLength();
    if (l_length + 2 > D_RADIUS_PACKET_MAX_LENGTH)
    {
        p_attr.init(this, 0);
        return RC_FAIL;
    }

    p_attr.init(this, l_length);
    p_attr.setType(p_attrType);
    return RC_SUCCESS;
}


// ---------------------------
// Get raw packet data
// ---------------------------
unsigned char * RadiusPacket::getRawData(void)
{
    return m_data;
}


// ---------------------------
// adjust packet's length
// ---------------------------
int RadiusPacket::adjustLength(uint16_t p_length)
{
    uint32_t l_length = getLength();
    if (l_length + p_length > D_RADIUS_PACKET_MAX_LENGTH)
        return RC_FAIL;

    setLength((uint16_t)(l_length + p_length));
    return RC_SUCCESS;
}


// ---------------------------
// Generate authenticator for response packet
// ---------------------------
bool RadiusPacket::responseAuthenticator(RadiusSecret * p_secret)
{
    // from RFC2865:
    //
    //   ResponseAuth =
    //      MD5(Code+ID+Length+RequestAuth+Attributes+Secret) where +
    //      denotes concatenation.
    //
    // (the authenticator field of this packet must hold RequestAuth)

    const unsigned char * l_secret;
    uint16_t l_secretLength;

    if (!resolveSecret(p_secret, l_secret, l_secretLength))
        return false;

    uint16_t l_length = getLength();

    unsigned char l_buf[D_RAW_DATA_LENGTH];
    memcpy(l_buf, m_data, l_length);
    memcpy(l_buf + l_length, l_secret, l_secretLength);

    unsigned char l_authenticator[D_AUTHENTICATOR_LENGTH];
    MD5Calc(l_authenticator, l_buf, l_length + l_secretLength);
    explicit_bzero(l_buf, sizeof(l_buf));

    setAuthenticator(l_authenticator);
    return true;
}


// ---------------------------
// Encode User-Password attribute
// ---------------------------
void RadiusPacket::encodeUserPassword(void)
{
    if (m_passwordLength > 0)
    {
        RadiusAttribute l_attr;
        l_attr.init(this, m_passwordOffset);
        l_attr.encodeUserPassword(m_password, m_passwordLength);
    }

    if (m_oldPasswordLength > 0)
    {
        RadiusAttribute l_attr;
        l_attr.init(this, m_oldPasswordOffset);
        l_attr.encodeOldPassword(m_oldPassword, m_oldPasswordLength);
    }
}


// ---------------------------
// Generate authenticator for accounting request packet
// ---------------------------
bool RadiusPacket::accountingRequestAuthenticator(RadiusSecret * p_secret) 
{
    // from RFC2866:
    //
    //     The Request Authenticator field in Accounting-Request packets contains a one-
    //     way MD5 hash calculated over a stream of octets consisting of the
    //     Code + Identifier + Length + 16 zero octets + request attributes +
    //     shared secret (where + indicates concatenation).
    //
    // RFC 5176 (Disconnect-Request / CoA-Request) uses the same algorithm.

    const unsigned char * l_secret;
    uint16_t l_secretLength;

    if (!resolveSecret(p_secret, l_secret, l_secretLength))
        return false;

    uint16_t l_length = getLength();

    unsigned char l_buf[D_RAW_DATA_LENGTH];
    memcpy(l_buf, m_data, l_length);
    memset(l_buf + 4, 0, D_AUTHENTICATOR_LENGTH);
    memcpy(l_buf + l_length, l_secret, l_secretLength);

    unsigned char l_authenticator[D_AUTHENTICATOR_LENGTH];
    MD5Calc(l_authenticator, l_buf, l_length + l_secretLength);
    explicit_bzero(l_buf, sizeof(l_buf));

    setAuthenticator(l_authenticator);
    return true;
}


// ---------------------------
// Verify the Request Authenticator of Accounting-Request / Disconnect-Request / CoA-Request
// ---------------------------
bool RadiusPacket::verifyRequestAuthenticator(RadiusSecret * p_secret)
{
    const unsigned char * l_secret;
    uint16_t l_secretLength;

    if (!m_valid || !resolveSecret(p_secret, l_secret, l_secretLength))
        return false;

    uint16_t l_length = getLength();

    unsigned char l_buf[D_RAW_DATA_LENGTH];
    memcpy(l_buf, m_data, l_length);
    memset(l_buf + 4, 0, D_AUTHENTICATOR_LENGTH);
    memcpy(l_buf + l_length, l_secret, l_secretLength);

    unsigned char l_authenticator[D_AUTHENTICATOR_LENGTH];
    MD5Calc(l_authenticator, l_buf, l_length + l_secretLength);
    explicit_bzero(l_buf, sizeof(l_buf));

    return ConstTimeEqual(l_authenticator, m_data + 4, D_AUTHENTICATOR_LENGTH) != 0;
}


/// Verify RADIUS response (this packet is the request)
bool RadiusPacket::verifyResponse(RadiusPacket & p_packet)
{
    if (!p_packet.isValid())
        return false;

    if (getID() != p_packet.getID())
        return false;

    const unsigned char * l_secret;
    uint16_t l_secretLength;

    if (!resolveSecret(NULL, l_secret, l_secretLength))
        return false;

    // for password change, old_password must be used instead of the original secret
    if (m_oldPasswordLength > 0)
    {
        l_secret = m_oldPassword;
        l_secretLength = m_oldPasswordLength;
    }

    uint16_t l_length = p_packet.getLength();

    // MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
    unsigned char l_buf[D_RAW_DATA_LENGTH];
    memcpy(l_buf, p_packet.getRawData(), l_length);
    memcpy(l_buf + 4, getAuthenticator(), D_AUTHENTICATOR_LENGTH);
    memcpy(l_buf + l_length, l_secret, l_secretLength);

    unsigned char l_authenticator[D_AUTHENTICATOR_LENGTH];
    MD5Calc(l_authenticator, l_buf, l_length + l_secretLength);
    explicit_bzero(l_buf, sizeof(l_buf));

    // compare the result with the received authenticator
    return ConstTimeEqual(l_authenticator, p_packet.getAuthenticator(), D_AUTHENTICATOR_LENGTH) != 0;
}


// ===========================
// Message-Authenticator (RFC 3579)
// ===========================

bool RadiusPacket::hasMessageAuthenticator(void)
{
    RadiusAttribute l_attr;
    return findAttribute(D_ATTR_MESSAGE_AUTHENTICATOR, l_attr) == RC_SUCCESS;
}


bool RadiusPacket::addMessageAuthenticator(void)
{
    if (hasMessageAuthenticator())
        return true;

    static const char l_zero[D_MESSAGE_AUTHENTICATOR_LENGTH] = {0};

    RadiusAttribute l_attr;
    if (addAttribute(D_ATTR_MESSAGE_AUTHENTICATOR, l_attr) != RC_SUCCESS)
        return false;

    return l_attr.setString(l_zero, D_MESSAGE_AUTHENTICATOR_LENGTH) == RC_SUCCESS;
}


// HMAC-MD5 over the whole packet, with the Message-Authenticator value zeroed
static bool calcMessageAuthenticator(RadiusPacket & p_packet, const unsigned char * p_authenticator,
                                     const unsigned char * p_secret, uint16_t p_secretLength,
                                     unsigned char p_out[D_MESSAGE_AUTHENTICATOR_LENGTH], unsigned char ** p_valuePtr)
{
    RadiusAttribute l_attr;
    if (p_packet.findAttribute(D_ATTR_MESSAGE_AUTHENTICATOR, l_attr) != RC_SUCCESS)
        return false;

    if (l_attr.getLength() != 2 + D_MESSAGE_AUTHENTICATOR_LENGTH)
        return false;

    uint16_t l_length = p_packet.getLength();
    unsigned char l_buf[D_RADIUS_PACKET_MAX_LENGTH];
    memcpy(l_buf, p_packet.getRawData(), l_length);

    if (p_authenticator != NULL)
        memcpy(l_buf + 4, p_authenticator, D_AUTHENTICATOR_LENGTH);

    // the value of the attribute starts 2 bytes after the attribute offset
    uint16_t l_valueOffset = l_attr.getOffset() + 2;
    memset(l_buf + l_valueOffset, 0, D_MESSAGE_AUTHENTICATOR_LENGTH);

    HMAC_MD5(p_out, p_secret, p_secretLength, l_buf, l_length);

    if (p_valuePtr)
        *p_valuePtr = p_packet.getRawData() + l_valueOffset;
    return true;
}


bool RadiusPacket::signMessageAuthenticator(RadiusSecret * p_secret)
{
    const unsigned char * l_secret;
    uint16_t l_secretLength;

    if (!resolveSecret(p_secret, l_secret, l_secretLength))
        return false;

    unsigned char l_hmac[D_MESSAGE_AUTHENTICATOR_LENGTH];
    unsigned char * l_value = NULL;
    if (!calcMessageAuthenticator(*this, NULL, l_secret, l_secretLength, l_hmac, &l_value))
        return false;

    memcpy(l_value, l_hmac, D_MESSAGE_AUTHENTICATOR_LENGTH);
    return true;
}


bool RadiusPacket::verifyMessageAuthenticator(const unsigned char * p_authenticator, RadiusSecret * p_secret)
{
    const unsigned char * l_secret;
    uint16_t l_secretLength;

    if (!m_valid || !resolveSecret(p_secret, l_secret, l_secretLength))
        return false;

    unsigned char l_hmac[D_MESSAGE_AUTHENTICATOR_LENGTH];
    unsigned char * l_value = NULL;
    if (!calcMessageAuthenticator(*this, p_authenticator, l_secret, l_secretLength, l_hmac, &l_value))
        return false;

    return ConstTimeEqual(l_hmac, l_value, D_MESSAGE_AUTHENTICATOR_LENGTH) != 0;
}

