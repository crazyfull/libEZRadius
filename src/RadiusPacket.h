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
#include <vector>


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

#define D_PACKET_MAX_KNOWN_CODE         45



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
    //INTEGER: the number. CHAP: CHAP identifier. VENDOR_SPECIFIC: Vendor-Id
    uint32_t intValue = 0;
    //STRING: raw bytes (may contain NULs). IP: dotted text. PASSWORD: decrypted PAP password.
    //CHAP: the 16 byte CHAP response. VENDOR_SPECIFIC: data after the Vendor-Id
    std::string strValue;
    AttrValueTypes ValueType = ATTR_TYPE_FORMAT_STRING;
    //true when the attribute exists in the packet and was decoded successfully
    bool valid = false;
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
    RadiusPacket(const RadiusPacket & p_packet) = default;
    RadiusPacket & operator=(const RadiusPacket & p_packet) = default;

    /// Destructor (wipes the plain text passwords kept in the packet)
    ~RadiusPacket();

    /// Load a packet received from the network.
    /// Returns false (and leaves an empty packet) when the data is not a well formed RADIUS packet:
    /// length 20..4096, length field <= DataLength, every attribute length >= 2 and inside the packet.
    /// Octets after the length given in the header are ignored (RFC 2865 section 3).
    bool setRawData(const char* Data, int DataLength);

    /// false when the packet was constructed from network data that failed validation
    bool isValid(void) const { return m_valid; }

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

    /// Get all attributes of the given type (attributes may repeat: Class, Reply-Message, Vendor-Specific ...)
    std::vector<AttrValue> getAttributes(RADIUSAttribute attrType);

    /// Add new attribute to the packet
    int addAttribute(unsigned char p_attrType, RadiusAttribute & p_attr);

    /// Get raw packet data
    unsigned char * getRawData(void);

    /// Adjust packet's length
    int adjustLength(uint16_t p_length);


    /// Generate authenticator for response packet.
    /// The authenticator field must contain the Request Authenticator before the call.
    /// Returns false when no (non empty) secret is available.
    bool responseAuthenticator(RadiusSecret * p_secret = NULL);

    /// Encode User-Password attribute
    void encodeUserPassword(void);


    /// Generate authenticator for accounting request packet (RFC 2866) and
    /// for CoA / Disconnect request packets (RFC 5176): same algorithm.
    bool accountingRequestAuthenticator(RadiusSecret * p_secret = NULL);

    /// Verify the Request Authenticator of a received Accounting-Request / Disconnect-Request /
    /// CoA-Request (MD5 over the packet with a zeroed authenticator + secret). Constant time compare.
    bool verifyRequestAuthenticator(RadiusSecret * p_secret = NULL);

    /// Verify RADIUS response (this packet = the request this response belongs to):
    /// identifier and Response Authenticator are checked. Constant time compare.
    bool verifyResponse(RadiusPacket & p_packet);

    // ---------------------------------------------------------------
    // Message-Authenticator (RFC 3579, HMAC-MD5). Recommended for every
    // Access-Request / Access-Response (BlastRADIUS, CVE-2024-3596)
    // ---------------------------------------------------------------

    /// true when the packet contains a Message-Authenticator attribute
    bool hasMessageAuthenticator(void);

    /// Add an empty (zeroed) Message-Authenticator attribute (no-op when it already exists)
    bool addMessageAuthenticator(void);

    /// Calculate and store the Message-Authenticator value. Call it after all other attributes
    /// are added and after the authenticator field has its final value
    /// (for a response: the Request Authenticator; the Response Authenticator is calculated afterwards).
    bool signMessageAuthenticator(RadiusSecret * p_secret = NULL);

    /// Verify the Message-Authenticator. p_authenticator: when not NULL it is used instead of the
    /// authenticator field of the packet (for a response: the Request Authenticator of the request).
    bool verifyMessageAuthenticator(const unsigned char * p_authenticator = NULL, RadiusSecret * p_secret = NULL);

    static AttrValueTypes getAttributeType(uint8_t attrType);
private:

    friend class RadiusAttribute;

    /// Init packet
    void init(unsigned char p_code);

    /// Clear packet content (secret is kept)
    void resetBody(void);

    /// secret to use: p_secret or the secret associated with the packet
    bool resolveSecret(RadiusSecret * p_secret, const unsigned char * & p_data, uint16_t & p_length);

    /// Generate pseudo-random authenticator
    void randomAuthenticator(void);

    /// Set packet's length
    void setLength(uint16_t p_length);

    /// Raw packet data
    unsigned char m_data[D_RAW_DATA_LENGTH+1];

    /// RADIUS secret associated with this packet
    RadiusSecret * m_secret;

    /// false when constructed from invalid network data
    bool m_valid;


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

