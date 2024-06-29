/*
 * This source file is part of the ace-radius library.  This code was
 * written by Alex Agranov in 2004-2009, and is covered by the BSD open source
 * license. Refer to the accompanying documentation for details on usage and
 * license.
 */

#ifndef _RADIUSPACKET_H__
#define _RADIUSPACKET_H__

#include "RadiusAttribute.h"
#include <string>


// Radius packet code values (from RFC2865)
// https://www.iana.org/assignments/radius-types/radius-types.xhtml
#define D_PACKET_ACCESS_REQUEST         1
#define D_PACKET_ACCESS_ACCEPT          2
#define D_PACKET_ACCESS_REJECT          3
#define D_PACKET_ACCOUNTING_REQUEST     4
#define D_PACKET_ACCOUNTING_RESPONSE    5
#define D_PACKET_ACCOUNTING_STATUS      6
/*
    "Password-Request",         // 7
    "Password-Ack",             // 8
    "Password-Reject",          // 9
    "Accounting-Message",       // 10
*/
#define D_PACKET_ACCOUNTING_MESSAGE     10
#define D_PACKET_ACCESS_CHALLENGE       11
#define D_PACKET_STATUS_SERVER          12
#define D_PACKET_STATUS_CLIENT          13

#define D_PACKET_MAX_KNOWN_CODE         42



// Some global constants (following RFC definitions)
#define D_RADIUS_PACKET_HEADER_LENGTH 20
#define D_RADIUS_PACKET_MAX_LENGTH    4096
#define D_AUTHENTICATOR_LENGTH        16

// Raw data buffer is used for storing the whole RADIUS packet _AND_ secret key
// (hence it should be D_RADIUS_PACKET_MAX_LENGTH + D_SECRET_MAX_LENGTH)
#define D_RAW_DATA_LENGTH           4352

enum AttrValueTypes{
    ATTR_TYPE_INTEGER = 1,
    ATTR_TYPE_IP_ADDRESS = 2,
    ATTR_TYPE_PASSWORD = 3,
    ATTR_TYPE_CHAP_PASSWORD = 4,
    ATTR_TYPE_VENDOR_SPECIFIC = 5,
    ATTR_TYPE_FORMAT_STRING = 6
};
struct AttrValue
{
    uint32_t intValue = 0;
    std::string strValue;
    AttrValueTypes ValueType = ATTR_TYPE_FORMAT_STRING;
};


class RadiusSecret;
class RadiusClientStack;
class RadiusPacket
{
public:

    /// Constructor
    RadiusPacket(const char* Data, int DataLength, unsigned char p_code = 0);
    RadiusPacket(unsigned char p_code, RadiusPacket & p_request);
    RadiusPacket(unsigned char p_code = 0);
    RadiusPacket(const RadiusPacket & p_packet);

    /// Destructor
    ~RadiusPacket();

    void setRawData(const char* Data, int DataLength);
    unsigned char getCode(void);

    /// Get packet code description
    const char *getCodeDescription(void);
    const char *getCodeDescription(unsigned char l_code);

    /// Get packet length
    uint16_t getLength(void);

    /// Get packet identifier
    unsigned char getID(void);
    
    /// Set packet identifier
    void setID(unsigned char p_id);

    /// Set random packet identifier
    void randomID();

    /// Get secret key used for packet encoding
    RadiusSecret * getSecret(void);
    
    /// Set secret key used for packet encoding
    void setSecret(RadiusSecret * p_secret);

    /// Set packet's code
    void setCode(unsigned char p_code);

    /// Get packet authenticator
    const unsigned char * getAuthenticator(void);
    
    /// Set packet authenticator
    void setAuthenticator(const unsigned char * p_auth);

    /// Dump radius packet in readable text format to the STDOUT
    void dump();

    /// Get first attribute in the packet
    int getFirstAttribute(RadiusAttribute & p_attr);

    /// Get next attribute in the packet
    int getNextAttribute(RadiusAttribute & p_attr);

    /// Find specific attribute in the packet
    int findAttribute(unsigned char p_attrType, RadiusAttribute & p_attr);
    AttrValue getAttribute(RADIUSAttribute attrType);

    /// Add new attribute to the packet
    int addAttribute(unsigned char p_attrType, RadiusAttribute & p_attr);

    /// Get raw packet data
    unsigned char * getRawData(void);

    /// Adjust packet's length
    int adjustLength(uint16_t p_length);


    /// Generate authenticator for response packet
    void responseAuthenticator(RadiusSecret * p_secret = NULL);

    /// Encode User-Password attribute
    void encodeUserPassword(void);


    /// Generate authenticator for accounting request packet
    void accountingRequestAuthenticator(RadiusSecret * p_secret = NULL);

    /// Verify RADIUS response
    bool verifyResponse(RadiusPacket & p_packet);

    AttrValueTypes getAttributeType(uint8_t attrType);
private:

    friend class RadiusAttribute;

    /// Init packet
    void init(unsigned char p_code);

    /// Generate pseudo-random authenticator
    void randomAuthenticator(void);

    /// Set packet's length
    void setLength(uint16_t p_length);

    /// Raw packet data
    unsigned char m_data[D_RAW_DATA_LENGTH+1];

    /// RADIUS secret associated with this packet
    RadiusSecret * m_secret;


    /// User-Password attribute in unencrypted format
    unsigned char m_password[D_USER_PASSWORD_MAX_LENGTH];
    uint16_t    m_passwordLength;
    uint16_t    m_passwordOffset;

    /// Old-Password attribute in unencrypted format
    unsigned char m_oldPassword[D_USER_PASSWORD_MAX_LENGTH];
    uint16_t    m_oldPasswordLength;
    uint16_t    m_oldPasswordOffset;
};

#endif // _RADIUSPACKET_H__

