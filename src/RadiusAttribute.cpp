/*
 * This source file is part of the ace-radius library.  This code was
 * written by Alex Agranov in 2004-2009, and is covered by the BSD open source
 * license. Refer to the accompanying documentation for details on usage and
 * license.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef _MSC_VER
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "RadiusAttribute.h"
#include "RadiusPacket.h"
#include "RadiusSecret.h"
#include "md5.h"


// the following table must be synchronized with definition of Attribute Types in CAttribute.h file
static const char *AttrTypeDescription[] =
{
    "unknown",                  // 0
    "User-Name",                // 1
    "User-Password",            // 2
    "CHAP-Password",            // 3
    "NAS-IP-Address",           // 4
    "NAS-Port",                 // 5
    "Service-Type",             // 6
    "Framed-Protocol",          // 7
    "Framed-IP-Address",        // 8
    "Framed-IP-Netmask",        // 9
    "Framed-Routing",           // 10
    "Filter-Id",                // 11
    "Framed-MTU",               // 12
    "Framed-Compression",       // 13
    "Login-IP-Host",            // 14
    "Login-Service",            // 15
    "Login-TCP-Port",           // 16
    "Unassigned",               // 17
    "Reply-Message",            // 18
    "Callback-Number",          // 19
    "Callback-Id",              // 20
    "Unassigned",               // 21
    "Framed-Route",             // 22
    "Framed-IPX-Network",       // 23
    "State",                    // 24
    "Class",                    // 25
    "Vendor-Specific",          // 26
    "Session-Timeout",          // 27
    "Idle-Timeout",             // 28
    "Termination-Action",       // 29
    "Called-Station-Id",        // 30
    "Calling-Station-Id",       // 31
    "NAS-Identifier",           // 32
    "Proxy-State",              // 33
    "Login-LAT-Service",        // 34
    "Login-LAT-Node",           // 35
    "Login-LAT-Group",          // 36
    "Framed-AppleTalk-Link",    // 37
    "Framed-AppleTalk-Network", // 38
    "Framed-AppleTalk-Zone",    // 39
    "Acct-Status-Type",         // 40
    "Acct-Delay-Time",          // 41
    "Acct-Input-Octets",        // 42
    "Acct-Output-Octets",       // 43
    "Acct-Session-Id",          // 44
    "Acct-Authentic",           // 45
    "Acct-Session-Time",        // 46
    "Acct-Input-Packets",       // 47
    "Acct-Output-Packets",      // 48
    "Acct-Terminate-Cause",     // 49
    "Acct-Multi-Session-Id",    // 50
    "Acct-Link-Count",          // 51
    "Acct-Input-Gigawords",     // 52
    "Acct-Output-Gigawords",    // 53
    "Unassigned",               // 54
    "Event-Timestamp",          // 55
    "Egress-VLANID",            // 56
    "Ingress-Filters",          // 57
    "Egress-VLAN-Name",         // 58
    "User-Priority-Table",      // 59
    "CHAP-Challenge",           // 60
    "NAS-Port-Type",            // 61
    "Port-Limit",               // 62
    "Login-LAT-Port",           // 63
    "Tunnel-Type",              // 64
    "Tunnel-Medium-Type",       // 65
    "Tunnel-Client-Endpoint",   // 66
    "Tunnel-Server-Endpoint",   // 67
    "Acct-Tunnel-Connection",   // 68
    "Tunnel-Password",          // 69
    "ARAP-Password",            // 70
    "ARAP-Features",            // 71
    "ARAP-Zone-Access",         // 72
    "ARAP-Security",            // 73
    "ARAP-Security-Data",       // 74
    "Password-Retry",           // 75
    "Prompt",                   // 76
    "Connect-Info",             // 77
    "Configuration-Token",      // 78
    "EAP-Message",              // 79
    "Message-Authenticator",    // 80
    "Tunnel-Private-Group-ID",  // 81
    "Tunnel-Assignment-ID",     // 82
    "Tunnel-Preference",        // 83
    "ARAP-Challenge-Response",  // 84
    "Acct-Interim-Interval"     // 85
};


static bool g_dumpPasswords = false;

void RadiusAttribute::setDumpPasswords(bool p_enable)
{
    g_dumpPasswords = p_enable;
}


// ---------------------------
// constructor
// ---------------------------
RadiusAttribute::RadiusAttribute() :
    m_packet(NULL),
    m_offset(0)
{
}


// ---------------------------
// destructor
// ---------------------------
RadiusAttribute::~RadiusAttribute()
{
}


// ---------------------------
// get pointer to the attribute raw data
// ---------------------------
unsigned char * RadiusAttribute::getRawData(void)
{
    return m_packet->getRawData() + m_offset + 2;
}


// ---------------------------
// attribute header is sane and the whole attribute lies inside the packet
// ---------------------------
bool RadiusAttribute::fits(uint8_t p_minLength)
{
    if (!isValid())
        return false;

    uint8_t l_length = getLength();
    if (l_length < 2 || l_length < p_minLength)
        return false;

    return (uint32_t)m_offset + l_length <= m_packet->getLength();
}

bool RadiusAttribute::isWellFormed(void)
{
    return fits(2);
}


// print printable characters, everything else as '.'
static void printText(const char * p_data, uint32_t p_length)
{
    printf("\"");
    for (uint32_t i = 0; i < p_length; i++)
    {
        unsigned char c = (unsigned char)p_data[i];
        printf("%c", (c >= ' ' && c <= '~') ? c : '.');
    }
    printf("\" ");
}


// ---------------------------
// dump attribute in readable text format to the text buffer
// ---------------------------
void RadiusAttribute::dump(AttributeFormat_e p_format)
{
    if (!isValid())
        return;

    // first print attribute type and description
    printf("%2u  %s (%u) = ", getLength(), getTypeDescription(), getType());

    // then print data in human-readable format
    switch (p_format)
    {
    case E_ATTR_FORMAT_INTEGER:
        if (fits(6))
            printf("%u ", getNumber());
        break;

    case E_ATTR_FORMAT_IP_ADDRESS:
        if (fits(6))
        {
            char l_buf[INET_ADDRSTRLEN];
            struct in_addr l_addr = getIPAddress();
            if (inet_ntop(AF_INET, &l_addr, l_buf, sizeof(l_buf)))
                printf("%s ", l_buf);
        }
        break;

    case E_ATTR_FORMAT_STRING:
    {
        const char * l_data = NULL;
        uint16_t l_length = 0;
        if (getString(l_data, l_length) == RC_SUCCESS)
            printText(l_data, l_length);
    }
        break;

    case E_ATTR_FORMAT_USER_PASSWORD:
    {
        if (!g_dumpPasswords)
        {
            printf("USER_PASSWORD: [hidden] ");
            break;
        }

        char l_data[D_USER_PASSWORD_MAX_LENGTH + 1];
        uint16_t l_length = 0;
        if (getUserPassword(l_data, l_length) == RC_SUCCESS)
        {
            l_data[l_length] = 0;
            printf("USER_PASSWORD: [%.*s] ", (int)l_length, l_data);
        }
        explicit_bzero(l_data, sizeof(l_data));
    }
        break;

    case E_ATTR_FORMAT_CHAP_PASSWORD:
        if (fits(3))
            printf("CHAP_ID: %u ", getChapIdentifier());
        break;

    case E_ATTR_FORMAT_VENDOR_SPECIFIC:
    {
        const char * l_data = NULL;
        uint16_t l_length = 0;
        if (fits(8) && getVendorString(l_data, l_length) == RC_SUCCESS)
        {
            printf("%u ", getVendorId());
            printText(l_data, l_length);
        }
    }
        break;
    }

    // then print data in HEX format
    uint16_t l_length = 0;
    if (fits(2))
        l_length = getLength() - 2;
    unsigned char * l_data = getRawData();

    printf("( ");
    for (uint32_t i=0; i < l_length; i++)
    {
        printf("%02x ", l_data[i]);
    }

    printf(")\n");
}


// ---------------------------
// dump attribute in readable text format to the text buffer
// ---------------------------
//inja moshakhas mikonim kodom Attibute ha noeshon chi hast
// https://www.iana.org/assignments/radius-types/radius-types.xhtml
void RadiusAttribute::dump()
{
    switch (RadiusPacket::getAttributeType(getType()))
    {
    case ATTR_TYPE_INTEGER:
        dump(E_ATTR_FORMAT_INTEGER);
        break;
    case ATTR_TYPE_IP_ADDRESS:
        dump(E_ATTR_FORMAT_IP_ADDRESS);
        break;
    case ATTR_TYPE_PASSWORD:
        dump(E_ATTR_FORMAT_USER_PASSWORD);
        break;
    case ATTR_TYPE_CHAP_PASSWORD:
        dump(E_ATTR_FORMAT_CHAP_PASSWORD);
        break;
    case ATTR_TYPE_VENDOR_SPECIFIC:
        dump(E_ATTR_FORMAT_VENDOR_SPECIFIC);
        break;
    default:
        dump(E_ATTR_FORMAT_STRING);
    }
}



// ---------------------------
// get attribute type
// ---------------------------
unsigned char RadiusAttribute::getType(void)
{
    if (!isValid())
        return 0;

    // A summary of the Attribute format is shown below.  The fields are
    // transmitted from left to right.
    //
    // 0                   1                   2
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
    // |     Type      |    Length     |  Value ...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

    unsigned char * l_data = m_packet->getRawData() + m_offset;
    return *l_data;
}


// ---------------------------
// set attribute type
// ---------------------------
int RadiusAttribute::setType(unsigned char p_type)
{
    if (!isValid())
        return RC_FAIL;

    unsigned char * l_data = m_packet->getRawData() + m_offset;
    *l_data = p_type;
    return RC_SUCCESS;
}


/// get textual description of attribute type
const char * RadiusAttribute::getTypeDescription(void)
{
    unsigned char l_type = getType();
    if ((l_type == 0) || (l_type > D_ATTR_MAX_KNOWN_TYPE))
        return AttrTypeDescription[0];
    else
        return AttrTypeDescription[l_type];
}


// ---------------------------
// get attribute's length
// ---------------------------
uint8_t RadiusAttribute::getLength(void)
{
    if (!isValid())
        return 0;

    uint8_t * l_data = m_packet->getRawData() + m_offset + 1;
    return *l_data;
}


// ---------------------------
// set attribute's length
// ---------------------------
int RadiusAttribute::setLength(unsigned char p_length)
{
    if (!isValid())
        return RC_FAIL;

    unsigned char * l_data = m_packet->getRawData() + m_offset + 1;
    *l_data = p_length;
    return RC_SUCCESS;
}


// ---------------------------
// attribute is valid?
// ---------------------------
int RadiusAttribute::isValid(void)
{
    return (m_packet != NULL) &&
           (m_offset >= D_RADIUS_PACKET_HEADER_LENGTH) &&
           (m_offset + 2 <= D_RADIUS_PACKET_MAX_LENGTH);
}


// ---------------------------
// init attribute
// ---------------------------
void RadiusAttribute::init(RadiusPacket * p_packet, uint16_t p_offset)
{
    m_packet = p_packet;
    m_offset = p_offset;
}


// ---------------------------
// get packet that this attribute belongs to
// ---------------------------
RadiusPacket * RadiusAttribute::getPacket(void)
{
    return m_packet;
}


// ---------------------------
// get attribute's offset inside the packet
// ---------------------------
uint16_t RadiusAttribute::getOffset(void)
{
    return m_offset;
}


// ---------------------------
// reserve p_length bytes (header included) for this NEW attribute at the end of the packet.
// The attribute length is a single byte, so p_length can not be bigger than 255.
// ---------------------------
int RadiusAttribute::reserve(uint16_t p_length)
{
    if (!isValid())
        return RC_FAIL;

    if (p_length < 2 || p_length > 2 + D_ATTR_MAX_VALUE_LENGTH)
        return RC_FAIL;

    // only an attribute that was just created with RadiusPacket::addAttribute() can be filled
    if (m_offset != m_packet->getLength())
        return RC_FAIL;

    // adjust packet's length
    if (m_packet->adjustLength(p_length) == RC_FAIL)
        return RC_FAIL;

    // encode attribute's length
    setLength((unsigned char)p_length);
    return RC_SUCCESS;
}


// ---------------------------
// undo reserve()
// ---------------------------
void RadiusAttribute::release(void)
{
    if (isValid() && m_offset < m_packet->getLength())
        m_packet->setLength(m_offset);
}


// ===========================
// Regular attributes
// ===========================

// ---------------------------
// get value of the integer attribute
// ---------------------------
uint32_t RadiusAttribute::getNumber(void)
{
    if (!fits(6))
        return 0;

    uint32_t l_value;
    memcpy(&l_value, getRawData(), sizeof(uint32_t));
    return ntohl(l_value);
}


// ---------------------------
// set value of the integer attribute
// ---------------------------
int RadiusAttribute::setNumber(uint32_t p_value)
{
    if (reserve(6) == RC_FAIL)
        return RC_FAIL;

    // encode attribute's data
    uint32_t l_value = htonl(p_value);
    memcpy(getRawData(), &l_value, sizeof(uint32_t));
    return RC_SUCCESS;
}


// ---------------------------
// get value of the IP address attribute
// ---------------------------
struct in_addr RadiusAttribute::getIPAddress(void)
{
    struct in_addr l_address;
    memset(&l_address, 0, sizeof(l_address));

    if (fits(6))
        memcpy(&l_address, getRawData(), sizeof(uint32_t));
    
    return l_address;
}


// ---------------------------
// set value of the IP address attribute
// ---------------------------
int RadiusAttribute::setIPAddress(struct in_addr p_address)
{
    if (reserve(6) == RC_FAIL)
        return RC_FAIL;

    // encode attribute's data
    memcpy(getRawData(), &p_address, sizeof(uint32_t));
    return RC_SUCCESS;
}


// ---------------------------
// get value of the string attribute
// ---------------------------
int RadiusAttribute::getString(const char * & p_data, uint16_t & p_length)
{
    p_data = NULL;
    p_length = 0;

    if (!fits(2))
        return RC_FAIL;
    
    p_data = (const char *)getRawData();
    p_length = getLength() - 2;     // 0 is a legal length (empty value)

    return RC_SUCCESS;
}


// ---------------------------
// set value of the string attribute
// p_length == 0: the data is a NULL terminated string
// ---------------------------
int RadiusAttribute::setString(const char * p_data, uint16_t p_length)
{
    if (p_data == NULL)
        return RC_FAIL;

    size_t l_dataLength = (p_length > 0) ? p_length : strlen(p_data);
    if (l_dataLength > D_ATTR_MAX_VALUE_LENGTH)
        return RC_FAIL;

    if (reserve((uint16_t)(l_dataLength + 2)) == RC_FAIL)
        return RC_FAIL;

    // encode attribute's data
    memcpy(getRawData(), p_data, l_dataLength);

    return RC_SUCCESS;
}


// ===========================
// Vendor-Specific attribute
// ===========================
//
//   A summary of the Vendor-Specific Attribute format is shown below.
//   The fields are transmitted from left to right.
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     Type      |  Length       |            Vendor-Id
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        Vendor-Id (cont)           |  String...
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-


// ---------------------------
// get vendor ID of Vendor-Specific attribute
// ---------------------------
uint32_t RadiusAttribute::getVendorId(void)
{
    if (getType() != D_ATTR_VENDOR_SPECIFIC || !fits(6))
        return 0;

    // get vendor Id
    uint32_t l_value;
    memcpy(&l_value, getRawData(), sizeof(uint32_t));
    return ntohl(l_value);
}


// ---------------------------
// set vendor ID of Vendor-Specific attribute
// ---------------------------
int RadiusAttribute::setVendorId(uint32_t p_vendorId)
{
    if (getType() != D_ATTR_VENDOR_SPECIFIC)
        return RC_FAIL;

    // encode vendor Id
    uint32_t l_vendorId = htonl(p_vendorId);
    memcpy(getRawData(), &l_vendorId, sizeof(uint32_t));
    return RC_SUCCESS;
}


// ---------------------------
// get "raw" string data of Vendor-Specific attribute
// ---------------------------
int RadiusAttribute::getVendorRawString(const char * & p_data, uint16_t & p_length)
{
    p_data = NULL;
    p_length = 0;

    if (!fits(6))
        return RC_FAIL;
    
    p_data = (const char *)getRawData() + 4;
    p_length = getLength() - 6;

    return RC_SUCCESS;
}


// ---------------------------
// set "raw" string data of Vendor-Specific attribute
// ---------------------------
int RadiusAttribute::setVendorRawString(const char * p_data, uint16_t p_length)
{
    if (p_data == NULL)
        return RC_FAIL;
    
    size_t l_dataLength = (p_length > 0) ? p_length : strlen(p_data);
    if (l_dataLength > D_ATTR_MAX_VALUE_LENGTH - 4)
        return RC_FAIL;

    if (reserve((uint16_t)(l_dataLength + 6)) == RC_FAIL)
        return RC_FAIL;

    // encode attribute's data
    memcpy(getRawData() + 4, p_data, l_dataLength);

    return RC_SUCCESS;
}


// ===========================
// User-Password attribute
// ===========================

// length of the (padded) encrypted password: multiple of 16, at least 16
static uint16_t paddedPasswordLength(uint16_t p_dataLength)
{
    if (p_dataLength == 0)
        return 16;
    return (uint16_t)((p_dataLength + 15) & ~15);
}

// ---------------------------
// set string data of User-Password attribute
// ---------------------------
int RadiusAttribute::setUserPassword(const char * p_data, uint16_t p_length)
{
    if (p_data == NULL)
        return RC_FAIL;

    size_t l_dataLength = (p_length == 0) ? strlen(p_data) : p_length;

    // RFC2865: User-Password is 16 to 128 octets
    if (l_dataLength > D_USER_PASSWORD_MAX_LENGTH)
        return RC_FAIL;

    // User-Password attribute's length should be multiple of 16
    uint16_t l_length = paddedPasswordLength((uint16_t)l_dataLength) + 2;

    if (reserve(l_length) == RC_FAIL)
        return RC_FAIL;

    // if RADIUS packet has secret key properly set, encode UserPassword attribute;
    // otherwise just store the unencrypted data inside the packet - when packet will be
    // sent to the network, it will be re-encoded
    RadiusSecret * l_secretKey = m_packet->getSecret();
    if (l_secretKey != NULL && !l_secretKey->isEmpty())
    {
        if (encodeUserPassword((const unsigned char *)p_data, (uint16_t)l_dataLength) != RC_SUCCESS)
        {
            release();
            return RC_FAIL;
        }
    }

    memcpy(m_packet->m_password, p_data, l_dataLength);
    m_packet->m_passwordLength = (uint16_t)l_dataLength;
    m_packet->m_passwordOffset = m_offset;

    return RC_SUCCESS;
}


// ---------------------------
// encode raw data of User-Password attribute
//
// we need this function in order to re-encode User-Password attribute with new secret key
// when packet is retransmitted through new connection;
//
// ---------------------------
int RadiusAttribute::encodeUserPassword(const unsigned char * p_data, uint16_t p_length)
{
    // from RFC2865
    //
    //     Call the shared secret S and the pseudo-random 128-bit Request
    //     Authenticator RA.  Break the password into 16-octet chunks p1, p2,
    //     etc.  with the last one padded at the end with nulls to a 16-octet
    //     boundary.  Call the ciphertext blocks c(1), c(2), etc.  We'll need
    //     intermediate values b1, b2, etc.
    //
    //        b1 = MD5(S + RA)       c(1) = p1 xor b1
    //        b2 = MD5(S + c(1))     c(2) = p2 xor b2
    //               .                       .
    //               .                       .
    //        bi = MD5(S + c(i-1))   c(i) = pi xor bi
    //
    //     The String will contain c(1)+c(2)+...+c(i) where + denotes
    //     concatenation.

    if (p_data == NULL || p_length > D_USER_PASSWORD_MAX_LENGTH || !fits(2 + 16))
        return RC_FAIL;

    // the attribute must be able to hold all the encrypted blocks
    uint16_t l_padded = paddedPasswordLength(p_length);
    if (l_padded != (uint16_t)(getLength() - 2))
        return RC_FAIL;

    // local pointer to the raw data buffer
    unsigned char *l_ptr = getRawData();

    int i;
    uint16_t l_chunkOffset, l_chunkLength;
    unsigned char b[16], c[16], p[16], md5Buf[D_SECRET_MAX_LENGTH+16];
    
    // init c(0) with pseudo-random RA
    memcpy(c, m_packet->getAuthenticator(), 16);

    // copy shared secret to the beginning of md5Buf
    const unsigned char * l_secret = NULL;
    uint16_t l_secretLength = 0;

    RadiusSecret * l_secretKey = m_packet->getSecret();
    if (l_secretKey != NULL)
        l_secretKey->getSecret(l_secret, l_secretLength);

    if (l_secretLength == 0)
        return RC_FAIL;

    memcpy(md5Buf, l_secret, l_secretLength);

    for (l_chunkOffset=0; l_chunkOffset<l_padded; l_chunkOffset += 16)
    {
        // calculate p(i)
        // (pad password to the 16-octet boundary with NULLs)
        l_chunkLength = (l_chunkOffset < p_length) ? (uint16_t)(p_length - l_chunkOffset) : 0;
        if (l_chunkLength >= 16)
            memcpy(p, p_data+l_chunkOffset, 16);
        else
        {
            if (l_chunkLength > 0)
                memcpy(p, p_data+l_chunkOffset, l_chunkLength);
            memset(p+l_chunkLength, 0, 16-l_chunkLength);
        }

        // calculate b(i) = MD5(S + c(i-1))
        memcpy(md5Buf + l_secretLength, c, 16);
        MD5Calc(b, md5Buf, l_secretLength+16);

        // calculate c(i) = p(i) xor b(i)
        for (i=0; i<16; i++)
        {
            c[i] = p[i] ^ b[i];
        }
        
        // copy c(i) to the attribute value
        memcpy(l_ptr, c, 16);
        l_ptr += 16;
    }

    explicit_bzero(p, sizeof(p));
    explicit_bzero(b, sizeof(b));
    explicit_bzero(md5Buf, sizeof(md5Buf));
    return RC_SUCCESS;
}


// ---------------------------
// get string data of User-Password attribute
// p_data must have room for D_USER_PASSWORD_MAX_LENGTH bytes
// ---------------------------
int RadiusAttribute::getUserPassword(char * p_data, uint16_t & p_length, RadiusSecret * p_secret)
{
    // from RFC2865
    //
    //     On receipt, the process of encoding is reversed to yield the original
    //     password.  bi = MD5(S + c(i-1)), p(i) = c(i) xor b(i)

    p_length = 0;

    // User-Password: 16 to 128 octets, always a multiple of 16
    if (p_data == NULL || !fits(2 + 16))
        return RC_FAIL;

    uint16_t l_attrLength = getLength() - 2;
    if (l_attrLength > D_USER_PASSWORD_MAX_LENGTH || (l_attrLength % 16) != 0)
        return RC_FAIL;

    // local pointer to the raw data buffer
    unsigned char *l_data = getRawData();

    int i;
    uint16_t l_chunkOffset;
    unsigned char b[16], c[16], p[16], md5Buf[D_SECRET_MAX_LENGTH+16];
    
    // local buffer for the decoded password
    char *l_ptr = p_data;

    // init c(0) with pseudo-random RA
    memcpy(c, m_packet->getAuthenticator(), 16);

    // copy shared secret to the beginning of md5Buf
    const unsigned char * l_secret = NULL;
    uint16_t l_secretLength = 0;
    
    if (p_secret != NULL)
        p_secret->getSecret(l_secret, l_secretLength);
    else
    {
        RadiusSecret * l_secretKey = m_packet->getSecret();
        if (l_secretKey != NULL)
            l_secretKey->getSecret(l_secret, l_secretLength);
    }
    
    if (l_secretLength == 0)
    {
        // no secret: use the plain text password that was stored by setUserPassword()
        if (m_packet->m_passwordLength > 0 && m_packet->m_passwordLength <= D_USER_PASSWORD_MAX_LENGTH)
        {
            p_length = m_packet->m_passwordLength;
            memcpy(p_data, m_packet->m_password, p_length);
            return RC_SUCCESS;
        }
        else
            return RC_FAIL;
    }

    memcpy(md5Buf, l_secret, l_secretLength);

    for (l_chunkOffset=0; l_chunkOffset<l_attrLength; l_chunkOffset += 16)
    {
        // calculate b(i) = MD5(S + c(i-1))
        memcpy(md5Buf + l_secretLength, c, 16);
        MD5Calc(b, md5Buf, l_secretLength+16);

        // calculate c(i)
        memcpy(c, l_data+l_chunkOffset, 16);

        // calculate p(i) = c(i) xor b(i)
        for (i=0; i<16; i++)
        {
            p[i] = c[i] ^ b[i];
        }
        
        // copy p(i) to the password value
        memcpy(l_ptr, p, 16);
        l_ptr += 16;
    }

    // decoded password length - remove padded NULLs
    p_length = l_attrLength;
    while ((p_length > 0) && (p_data[p_length-1] == '\0'))
    {
        --p_length;
    }

    explicit_bzero(p, sizeof(p));
    explicit_bzero(b, sizeof(b));
    explicit_bzero(md5Buf, sizeof(md5Buf));
    return RC_SUCCESS;
}


// ===========================
// Old-Password attribute (legacy)
// ===========================

// ---------------------------
// set string data of Old-Password attribute
// ---------------------------
int RadiusAttribute::setOldPassword(const char * p_data, uint16_t p_length)
{
    if (p_data == NULL)
        return RC_FAIL;

    size_t l_dataLength = (p_length == 0) ? strlen(p_data) : p_length;
    if (l_dataLength > D_USER_PASSWORD_MAX_LENGTH)
        return RC_FAIL;

    // Old-Password attribute's length should be multiple of 16
    uint16_t l_length = paddedPasswordLength((uint16_t)l_dataLength) + 2;

    if (reserve(l_length) == RC_FAIL)
        return RC_FAIL;

    // if RADIUS packet has secret key properly set, encode Old-Password attribute;
    // otherwise just store the unencrypted data inside the packet - when packet will be
    // sent to the network, it will be re-encoded
    RadiusSecret * l_secretKey = m_packet->getSecret();
    if (l_secretKey != NULL && !l_secretKey->isEmpty())
    {
        if (encodeOldPassword((const unsigned char *)p_data, (uint16_t)l_dataLength) != RC_SUCCESS)
        {
            release();
            return RC_FAIL;
        }
    }

    memcpy(m_packet->m_oldPassword, p_data, l_dataLength);
    m_packet->m_oldPasswordLength = (uint16_t)l_dataLength;
    m_packet->m_oldPasswordOffset = m_offset;

    return RC_SUCCESS;
}


// ---------------------------
// encode raw data of Old-Password attribute
// (same as encodeUserPassword)
// ---------------------------
int RadiusAttribute::encodeOldPassword(const unsigned char * p_data, uint16_t p_length)
{
    // the encoding of the legacy Old-Password attribute is the same as the one of User-Password
    return encodeUserPassword(p_data, p_length);
}


// ---------------------------
// get string data of Old-Password attribute
// ---------------------------
int RadiusAttribute::getOldPassword(char * p_data, uint16_t & p_length, RadiusSecret * p_secret)
{
    p_length = 0;

    if (p_data == NULL || !fits(2 + 16))
        return RC_FAIL;

    uint16_t l_attrLength = getLength() - 2;
    if (l_attrLength > D_USER_PASSWORD_MAX_LENGTH || (l_attrLength % 16) != 0)
        return RC_FAIL;

    unsigned char *l_data = getRawData();

    int i;
    uint16_t l_chunkOffset;
    unsigned char b[16], c[16], p[16], md5Buf[D_SECRET_MAX_LENGTH+16];
    char *l_ptr = p_data;

    memcpy(c, m_packet->getAuthenticator(), 16);

    const unsigned char * l_secret = NULL;
    uint16_t l_secretLength = 0;
    
    if (p_secret != NULL)
        p_secret->getSecret(l_secret, l_secretLength);
    else
    {
        RadiusSecret * l_secretKey = m_packet->getSecret();
        if (l_secretKey != NULL)
            l_secretKey->getSecret(l_secret, l_secretLength);
    }
    
    if (l_secretLength == 0)
    {
        if (m_packet->m_oldPasswordLength > 0 && m_packet->m_oldPasswordLength <= D_USER_PASSWORD_MAX_LENGTH)
        {
            p_length = m_packet->m_oldPasswordLength;
            memcpy(p_data, m_packet->m_oldPassword, p_length);
            return RC_SUCCESS;
        }
        else
            return RC_FAIL;
    }

    memcpy(md5Buf, l_secret, l_secretLength);

    for (l_chunkOffset=0; l_chunkOffset<l_attrLength; l_chunkOffset += 16)
    {
        memcpy(md5Buf + l_secretLength, c, 16);
        MD5Calc(b, md5Buf, l_secretLength+16);

        memcpy(c, l_data+l_chunkOffset, 16);

        for (i=0; i<16; i++)
        {
            p[i] = c[i] ^ b[i];
        }
        
        memcpy(l_ptr, p, 16);
        l_ptr += 16;
    }

    p_length = l_attrLength;
    while ((p_length > 0) && (p_data[p_length-1] == '\0'))
    {
        --p_length;
    }

    explicit_bzero(p, sizeof(p));
    explicit_bzero(b, sizeof(b));
    explicit_bzero(md5Buf, sizeof(md5Buf));
    return RC_SUCCESS;
}


// ===========================
// CHAP-Password attribute
// ===========================
//
//    0                   1                   2
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
//   |     Type      |    Length     |  CHAP Ident   |  String ...
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-


// ---------------------------
// get CHAP identifier of CHAP-Password attribute
// ---------------------------
unsigned char RadiusAttribute::getChapIdentifier(void)
{
    if (!fits(3))
        return 0;

    unsigned char * l_data = getRawData();
    return *l_data;
}


// ---------------------------
// set CHAP identifier of CHAP-Password attribute
// (it can be called before or after setChapString)
// ---------------------------
int RadiusAttribute::setChapIdentifier(unsigned char p_chapId)
{
    if (!isValid())
        return RC_FAIL;

    unsigned char * l_data = getRawData();
    *l_data = p_chapId;
    return RC_SUCCESS;
}


// ---------------------------
// get string data of CHAP-Password attribute
// ---------------------------
int RadiusAttribute::getChapString(const char *&p_data, uint16_t & p_length)
{
    p_data = NULL;
    p_length = 0;

    if (!fits(3))
        return RC_FAIL;
    
    p_data = (const char *)getRawData() + 1;
    p_length = getLength() - 3;

    return RC_SUCCESS;
}

// ---------------------------
// set string data of CHAP-Password attribute
// ---------------------------
int RadiusAttribute::setChapString(const char * p_data, uint16_t p_length)
{
    if (p_data == NULL)
        return RC_FAIL;

    size_t l_dataLength = (p_length > 0) ? p_length : strlen(p_data);
    if (l_dataLength > D_ATTR_MAX_VALUE_LENGTH - 1)
        return RC_FAIL;

    // the identifier byte (set by setChapIdentifier) must survive
    unsigned char l_ident = 0;
    if (isValid())
        l_ident = *getRawData();

    if (reserve((uint16_t)(l_dataLength + 3)) == RC_FAIL)
        return RC_FAIL;

    // encode attribute's data
    unsigned char * l_data = getRawData();
    l_data[0] = l_ident;
    memcpy(l_data + 1, p_data, l_dataLength);

    return RC_SUCCESS;
}



/*
    Additional access methods for Vendor-Specific attributes

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |     Type      |  Length       |            Vendor-Id
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           Vendor-Id (cont)           | Vendor type   | Vendor length |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |    Attribute-Specific...
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
*/


// ---------------------------
// get Vendor Type field
// ---------------------------
unsigned char RadiusAttribute::getVendorType()
{
    if (!fits(8))
        return 0;

    unsigned char * l_ptr = getRawData() + 4;
    return *l_ptr;
}


// ---------------------------
// set Vendor Type field
// ---------------------------
int RadiusAttribute::setVendorType(unsigned char p_value)
{
    if (!isValid())
        return RC_FAIL;

    unsigned char * l_ptr = getRawData() + 4;
    *l_ptr = p_value;

    return RC_SUCCESS;
}


// ---------------------------
// get Vendor Length field
// ---------------------------
unsigned char RadiusAttribute::getVendorLength()
{
    if (!fits(8))
        return 0;

    unsigned char * l_ptr = getRawData() + 5;
    return *l_ptr;
}


// ---------------------------
// set Vendor Length field
// ---------------------------
int RadiusAttribute::setVendorLength(unsigned char p_length)
{
    if (!isValid())
        return RC_FAIL;

    unsigned char * l_ptr = getRawData() + 5;
    *l_ptr = p_length;

    return RC_SUCCESS;
}


// ---------------------------
// get value of the integer Vendor-Specific attribute
// ---------------------------
uint32_t RadiusAttribute::getVendorNumber()
{
    if (!fits(12))
        return 0;
    
    uint32_t l_value;
    memcpy(&l_value, getRawData()+6, sizeof(uint32_t));
    return ntohl(l_value);
}


// ---------------------------
// set value of the integer Vendor-Specific attribute
// ---------------------------
int RadiusAttribute::setVendorNumber(uint32_t p_value)
{
    // keep Vendor-Id and Vendor type that were set before
    if (reserve(12) == RC_FAIL)
        return RC_FAIL;

    setVendorLength(12 - 6);

    // encode attribute's data
    uint32_t l_value = htonl(p_value);
    memcpy(getRawData()+ 6, &l_value, sizeof(uint32_t));
    return RC_SUCCESS;

}


// ---------------------------
// get value of the string Vendor-Specific attribute
// ---------------------------
int RadiusAttribute::getVendorString(const char * & p_data, uint16_t & p_length)
{
    p_data = NULL;
    p_length = 0;

    if (!fits(8))
        return RC_FAIL;
    
    p_data = (const char *)getRawData() + 6;
    p_length = getLength() - 8;

    return RC_SUCCESS;
}


// ---------------------------
// set value of the string Vendor-Specific attribute
// ---------------------------
int RadiusAttribute::setVendorString(const char * p_data, uint16_t p_length)
{
    if (p_data == NULL)
        return RC_FAIL;

    size_t l_dataLength = (p_length > 0) ? p_length : strlen(p_data);
    if (l_dataLength > D_ATTR_MAX_VALUE_LENGTH - 6)
        return RC_FAIL;

    uint16_t l_length = (uint16_t)(l_dataLength + 8);
    if (reserve(l_length) == RC_FAIL)
        return RC_FAIL;

    setVendorLength((unsigned char)(l_length - 6));

    // encode attribute's data
    unsigned char * l_data = getRawData() + 6;
    memcpy(l_data, p_data, l_dataLength);

    return RC_SUCCESS;

}


// ---------------------------
// get value of the IP address Vendor-Specific attribute
// ---------------------------
struct in_addr RadiusAttribute::getVendorIPAddress()
{
    struct in_addr l_address;
    memset(&l_address, 0, sizeof(l_address));

    if (fits(12))
        memcpy(&l_address, getRawData()+6, sizeof(uint32_t));
    
    return l_address;
}


// ---------------------------
// set value of the IP address Vendor-Specific attribute
// ---------------------------
int RadiusAttribute::setVendorIPAddress(struct in_addr p_address)   
{
    if (reserve(12) == RC_FAIL)
        return RC_FAIL;

    setVendorLength(12 - 6);
    
    // encode attribute's data
    memcpy(getRawData()+6, &p_address, sizeof(uint32_t));
    return RC_SUCCESS;
}


// ---------------------------
// set a complete Vendor-Specific attribute in one call (standard RFC 2865 vendor format):
//   Vendor-Id (4 bytes) | Vendor-Type (1) | Vendor-Length (1) | data
// Example: Mikrotik-Rate-Limit => vendorId = 14988, vendorType = 8, data = "10M/10M"
// ---------------------------
int RadiusAttribute::setVendorAttribute(uint32_t p_vendorId, unsigned char p_vendorType, const void * p_data, uint16_t p_length)
{
    if (p_data == NULL && p_length > 0)
        return RC_FAIL;

    if (p_length > D_ATTR_MAX_VALUE_LENGTH - 6)
        return RC_FAIL;

    setType(D_ATTR_VENDOR_SPECIFIC);

    uint16_t l_length = (uint16_t)(p_length + 8);
    if (reserve(l_length) == RC_FAIL)
        return RC_FAIL;

    setVendorId(p_vendorId);
    setVendorType(p_vendorType);
    setVendorLength((unsigned char)(p_length + 2));
    if (p_length > 0)
        memcpy(getRawData() + 6, p_data, p_length);
    return RC_SUCCESS;
}

