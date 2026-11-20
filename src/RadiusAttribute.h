/*
 * This source file is part of the ace-radius library.  This code was
 * written by Alex Agranov in 2004-2009, and is covered by the BSD open source
 * license. Refer to the accompanying documentation for details on usage and
 * license.
 */

#ifndef _RADIUSATTRIBUTE_H__
#define _RADIUSATTRIBUTE_H__

#include "Radius.h"

// definition of Attribute Types from RFC2865
// https://www.iana.org/assignments/radius-types/radius-types.xhtml
#define D_MAX_PASSWORD_LENGTH 256

enum RADIUSAttribute {
    USER_NAME = 1,
    USER_PASSWORD = 2,
    CHAP_PASSWORD = 3,
    NAS_IP_ADDRESS = 4,
    NAS_PORT = 5,
    SERVICE_TYPE = 6,
    FRAMED_PROTOCOL = 7,
    FRAMED_IP_ADDRESS = 8,
    FRAMED_IP_NETMASK = 9,
    FRAMED_ROUTING = 10,
    FILTER_ID = 11,
    FRAMED_MTU = 12,
    FRAMED_COMPRESSION = 13,
    LOGIN_IP_HOST = 14,
    LOGIN_SERVICE = 15,
    LOGIN_TCP_PORT = 16,
    OLD_PASSWORD = 17,
    REPLY_MESSAGE = 18,
    CALLBACK_NUMBER = 19,
    CALLBACK_ID = 20,
    FRAMED_ROUTE = 22,
    FRAMED_IPX_NETWORK = 23,
    STATE = 24,
    CLASS = 25,
    VENDOR_SPECIFIC = 26,
    SESSION_TIMEOUT = 27,
    IDLE_TIMEOUT = 28,
    TERMINATION_ACTION = 29,
    CALLED_STATION_ID = 30,
    CALLING_STATION_ID = 31,
    NAS_IDENTIFIER = 32,
    PROXY_STATE = 33,
    LOGIN_LAT_SERVICE = 34,
    LOGIN_LAT_NODE = 35,
    LOGIN_LAT_GROUP = 36,
    FRAMED_APPLETALK_LINK = 37,
    FRAMED_APPLETALK_NETWORK = 38,
    FRAMED_APPLETALK_ZONE = 39,
    ACCT_STATUS_TYPE = 40,
    ACCT_DELAY_TIME = 41,
    ACCT_INPUT_OCTETS = 42,
    ACCT_OUTPUT_OCTETS = 43,
    ACCT_SESSION_ID = 44,
    ACCT_AUTHENTIC = 45,
    ACCT_SESSION_TIME = 46,
    ACCT_INPUT_PACKETS = 47,
    ACCT_OUTPUT_PACKETS = 48,
    ACCT_TERMINATE_CAUSE = 49,
    ACCT_MULTI_SESSION_ID = 50,
    ACCT_LINK_COUNT = 51,
    ACCT_INPUT_GIGAWORDS = 52,
    ACCT_OUTPUT_GIGAWORDS = 53,
    EVENT_TIMESTAMP = 55,
    EGRESS_VLANID = 56,
    INGRESS_FILTERS = 57,
    EGRESS_VLAN_NAME = 58,
    USER_PRIORITY_TABLE = 59,
    CHAP_CHALLENGE = 60,
    NAS_PORT_TYPE = 61,
    PORT_LIMIT = 62,
    LOGIN_LAT_PROMPT = 63,
    TUNNEL_TYPE = 64,
    TUNNEL_MEDIUM_TYPE = 65,
    TUNNEL_CLIENT_ENDPOINT = 66,
    TUNNEL_SERVER_ENDPOINT = 67,
    ACCT_TUNNEL_CONNECTION = 68,
    TUNNEL_PASSWORD = 69,
    ARAP_PASSWORD = 70,
    ARAP_FEATURES = 71,
    ARAP_ZONE_ACCESS = 72,
    ARAP_SECURITY = 73,
    ARAP_SECURITY_DATA = 74,
    PASSWORD_RETRY = 75,
    PROMPT = 76,
    CONNECT_INFO = 77,
    CONFIGURRATION_TOKEN = 78,
    EAP_MESSAGE = 79,
    MESSAGE_AUTHENTICATOR = 80,
    TUNNEL_PRIVATE_GOUP_ID = 81,
    TUNNEL_ASSIGMENT_ID = 82,
    TUNNEL_PREFERENCE = 83,
    ARAP_CHALLENGE_RESPONSE = 84,
    ACCT_INTERIM_INTRAVEL = 85,

    // correctly spelled aliases (the old misspelled names are kept for compatibility)
    ACCT_INTERIM_INTERVAL = 85,
    LOGIN_LAT_PORT = 63,
    CONFIGURATION_TOKEN = 78,
    TUNNEL_PRIVATE_GROUP_ID = 81,
    TUNNEL_ASSIGNMENT_ID = 82
};

// RADIUS Packet Type Codes
enum RADIUSPacketTypeCodes
{
    UNKNOWN = 0,
    ACCESS_REQUEST = 1,
    ACCESS_ACCEPT = 2,
    ACCESS_REJECT = 3,
    ACCOUNTING_REQUEST = 4,
    ACCOUNTING_RESPONSE = 5,
    ACCOUNTING_STATUS = 6,
    PASSWORD_REQUEST = 7,
    PASSWORD_ACK = 8,
    PASSWORD_REJECT = 9,
    ACCOUNTING_MESSAGE = 10,
    ACCESS_CHALLENGE = 11,
    STATUS_SERVER = 12,
    STATUS_CLIENT = 13,
    RESOURCE_FREE_REQUEST = 21,
    RESOURCE_FREE_RESPONSE = 22,
    RESOURCE_QUERY_REQUEST = 23,
    RESOURCE_QUERY_RESPONSE = 24,
    ALTERNATE_RESOURCE_RECLAIM_REQUEST = 25,
    NAS_REBOOT_REQUEST = 26,
    NAS_REBOOT_RESPONSE = 27,
    NEXT_PASSCODE = 30,
    NEW_PIN = 31,
    TERMINATE_SESSION = 32,
    PASSWORD_EXPIRED = 33,
    DISCONNECT_REQUEST = 40,
    DISCONNECT_ACK = 41,
    DISCONNECT_NAK = 42,
    COA_REQUEST = 43,
    COA_ACK = 44,
    COA_NAK = 45
};


enum RADIUSClientRequestType
{
    C_ACCESS_REQUEST = 1,
    C_ACCOUNTING_REQUEST = 4
};

// Values for RADIUS Attribute, Acct-Status-Type
enum class RADIUSAcctStatusType {
    START = 1,
    STOP = 2,
    INTERIM_UPDATE = 3,
    // 4, 5, 6 reserved
    ON = 7,
    OFF = 8,
};

#define D_ATTR_USER_NAME                1
#define D_ATTR_USER_PASSWORD            2
#define D_ATTR_CHAP_PASSWORD            3
#define D_ATTR_NAS_IP_ADDRESS           4
#define D_ATTR_NAS_PORT                 5
#define D_ATTR_SERVICE_TYPE             6
#define D_ATTR_FRAMED_PROTOCOL          7
#define D_ATTR_FRAMED_IP_ADDRESS        8
#define D_ATTR_FRAMED_IP_NETMASK        9
#define D_ATTR_FRAMED_ROUTING           10 
#define D_ATTR_FILTER_ID                11 
#define D_ATTR_FRAMED_MTU               12 
#define D_ATTR_FRAMED_COMPRESSION       13 
#define D_ATTR_LOGIN_IP_HOST            14 
#define D_ATTR_LOGIN_SERVICE            15 
#define D_ATTR_LOGIN_TCP_PORT           16 
#define D_ATTR_OLD_PASSWORD             17
#define D_ATTR_REPLY_MESSAGE            18 
#define D_ATTR_CALLBACK_NUMBER          19 
#define D_ATTR_CALLBACK_ID              20 
#define D_ATTR_FRAMED_ROUTE             22 
#define D_ATTR_FRAMED_IPX_NETWORK       23 
#define D_ATTR_STATE                    24 
#define D_ATTR_CLASS                    25 
#define D_ATTR_VENDOR_SPECIFIC          26 
#define D_ATTR_SESSION_TIMEOUT          27 
#define D_ATTR_IDLE_TIMEOUT             28 
#define D_ATTR_TERMINATION_ACTION       29 
#define D_ATTR_CALLED_STATION_ID        30 
#define D_ATTR_CALLING_STATION_ID       31 
#define D_ATTR_NAS_IDENTIFIER           32 
#define D_ATTR_PROXY_STATE              33 
#define D_ATTR_LOGIN_LAT_SERVICE        34 
#define D_ATTR_LOGIN_LAT_NODE           35 
#define D_ATTR_LOGIN_LAT_GROUP          36 
#define D_ATTR_FRAMED_APPLETALK_LINK    37 
#define D_ATTR_FRAMED_APPLETALK_NETWORK 38 
#define D_ATTR_FRAMED_APPLETALK_ZONE    39
#define D_ATTR_ACCT_STATUS_TYPE         40
#define D_ATTR_ACCT_DELAY_TIME          41
#define D_ATTR_ACCT_INPUT_OCTETS        42
#define D_ATTR_ACCT_OUTPUT_OCTETS       43
#define D_ATTR_ACCT_SESSION_ID          44
#define D_ATTR_ACCT_AUTHENTIC           45
#define D_ATTR_ACCT_SESSION_TIME        46
#define D_ATTR_ACCT_INPUT_PACKETS       47
#define D_ATTR_ACCT_OUTPUT_PACKETS      48
#define D_ATTR_ACCT_TERMINATE_CAUSE     49
#define D_ATTR_ACCT_MULTI_SESSION_ID    50
#define D_ATTR_ACCT_LINK_COUNT          51
#define D_ATTR_ACCT_INPUT_GIGAWORDS     52
#define D_ATTR_ACCT_OUTPUT_GIGAWORDS    53
#define D_ATTR_UNASSIGNED               54
#define D_ATTR_EVENT_TIMESTAMP          55
#define D_ATTR_EGRESS_VLANID            56
#define D_ATTR_INGRESS_FILTERS          57
#define D_ATTR_EGRESS_VLAN_NAME         58
#define D_ATTR_USER_PRIORITY_TABLE      59
#define D_ATTR_CHAP_CHALLENGE           60
#define D_ATTR_CHAP_CHALLENGE           60 
#define D_ATTR_NAS_PORT_TYPE            61 
#define D_ATTR_PORT_LIMIT               62 
#define D_ATTR_LOGIN_LAT_PROMPT         63
#define D_ATTR_TUNNEL_TYPE              64
#define D_ATTR_TUNNEL_MEDIUM_TYPE       65
#define D_ATTR_TUNNEL_CLIENT_ENDPOINT   66
#define D_ATTR_TUNNEL_SERVER_ENDPOINT   67
#define D_ATTR_ACCT_TUNNEL_CONNECTION   68
#define D_ATTR_TUNNEL_PASSWORD          69
#define D_ATTR_ARAP_PASSWORD            70
#define D_ATTR_ARAP_FEATURES            71
#define D_ATTR_ARAP_ZONE_ACCESS         72
#define D_ATTR_ARAP_SECURITY            73
#define D_ATTR_ARAP_SECURITY_DATA       74
#define D_ATTR_PASSWORD_RETRY           75
#define D_ATTR_PROMPT                   76
#define D_ATTR_CONNECT_INFO             77
#define D_ATTR_CONFIGURRATION_TOKEN     78
#define D_ATTR_EAP_MESSAGE              79
#define D_ATTR_MESSAGE_AUTHENTICATOR    80
#define D_ATTR_TUNNEL_PRIVATE_GOUP_ID   81
#define D_ATTR_TUNNEL_ASSIGMENT_ID      82
#define D_ATTR_TUNNEL_PREFERENCE        83
#define D_ATTR_ARAP_CHALLENGE_RESPONSE  84
#define D_ATTR_ACCT_INTERIM_INTRAVEL    85
#define D_ATTR_ACCT_INTERIM_INTERVAL    85


#define D_ATTR_MAX_KNOWN_TYPE           85


// definition of Acct-Status-Type attribute values from RFC2866
// https://www.iana.org/assignments/radius-types/radius-types.xhtml#radius-types-10
#define D_ACCT_STATUS_START             1
#define D_ACCT_STATUS_STOP              2
#define D_ACCT_STATUS_INTERIM_UPDATE    3
/*4 ,5 ,6 Reserved*/
#define D_ACCT_STATUS_ON                7
#define D_ACCT_STATUS_OFF               8





// max length of User-Password attribute
#define D_USER_PASSWORD_MAX_LENGTH    128
#define CHAP_VALUE_LENGTH             16

// max length of the value of a single attribute (RFC 2865: attribute length is 1 byte, 2 bytes are header)
#define D_ATTR_MAX_VALUE_LENGTH       253
// Message-Authenticator (RFC 3579) value length (HMAC-MD5)
#define D_MESSAGE_AUTHENTICATOR_LENGTH 16


class RadiusPacket;
class RadiusSecret;

/**
 * @class RadiusAttribute
 *
 * @brief Implementation of RADIUS attribute
 *
 * This class does not keep any data - instead it provides methods to
 * properly access and encode data at specific offset inside the RADIUS
 * packet raw data buffer. 
 *
 * This implementation minimizes the footprint of RADIUS stack and
 * does not require dynamic memory allocations. It's also very fast
 * (at least in the typical RADIUS applications) since the data is
 * immediately encoded inside the packet.
 *
 */
class RadiusAttribute
{
public:

    /// Constructor
    RadiusAttribute();
    
    /// Destructor
    ~RadiusAttribute();

    
    /// Dump attribute in readable text format to the STDOUT
    void dump();

    /// By default dump() hides decrypted passwords. Enable only for debugging.
    static void setDumpPasswords(bool p_enable);

    /// true when the attribute header is sane and the whole attribute lies inside the packet
    bool isWellFormed(void);

    
    /// Init attribute
    /**
     * Set associated RADIUS packet and offset in it - this will effectively
     * init the attribute. A special usage is to pass zero p_offset - this
     * will mark attribute "invalid".
     *
     * @param[in] p_packet - RADIUS packet
     * @param[in] p_offset - offset inside the packet's raw data
     */
    void init(RadiusPacket * p_packet, uint16_t p_offset);

    
    /// Get packet that this attribute belongs to
    RadiusPacket * getPacket(void);


    /// Get attribute's offset inside the packet
    uint16_t getOffset(void);


    ///////////////////////////////////////////////////////////////////////

    /// Get attribute type
    /**
     * @return attribute type
     */
    unsigned char getType(void);

    /// Set attribute type
    /**
     * Set attribute type
     *
     * @param[in] p_code - attribute code
     * @return RC_SUCCESS or RC_FAIL
     */
    int setType(unsigned char p_type);

    
    /// Get textual description of attribute type
    const char * getTypeDescription(void);


    /// Get attribute length
    /**
     * Note that returned value is length of the attribute data block 
     * as encoded in raw RADIUS packet (in other words it's simply
     * a value of Length octet in attribute data).
     * You must take into account specific attribute type in order to
     * calculate the "real data" length.
     *
     * @return attribute's length
     */
    uint8_t getLength(void);

    /// Set attribute length
    /**
     * Set attribute's length - refer to getLength() description for details.
     *
     * @param[in] p_length - attribute's length
     * @return RC_SUCCESS or RC_FAIL
     */
    int setLength(unsigned char p_length);

    
    /// Attribute is valid?
    /**
     * @return TRUE or FALSE
     */
    int isValid(void);


    // ------------------------------------------------------------
    // get- and set- methods - access data stored in the attribute

    // ===========================
    // Regular attributes
    // ===========================

    /// Get value of the numeric attribute
    /**
     * @return value of numeric attribute in host order format
     */
    uint32_t getNumber(void);
    
    /// Set value of the numeric attribute
    /**
     * @param[in] p_value - numeric value in host order format
     * @return RC_SUCCESS if attribute is successfully encode; RC_FAIL otherwise
     */
    int setNumber(uint32_t p_value);


    /// Get value of the IP address attribute
    /**
     * @return value of IP address attribute
     */
    struct in_addr getIPAddress(void);

    /// Set value of the IP address attribute
    /**
     * @param[in] p_value - IP address
     * @return RC_SUCCESS if attribute is successfully encode; RC_FAIL otherwise
     */
    int setIPAddress(struct in_addr p_value);


    /// Get value of the string attribute
    /**
     * Note that string data may contain both readable characters 
     * and non-readable binary data. In any case string will not be 
     * null-terminated, hence you should use returned p_length value 
     * to properly operate on it. 
     *
     * @param[out] p_data   - pointer to the beginning of string data
     * @param[out] p_length - string length
     * @return RC_SUCCESS or RC_FAIL
     */
    int getString(const char * & p_data, uint16_t & p_length);
    
    /// Set value of the string attribute
    /**
     * Note that string data may contain both readable characters 
     * and non-readable binary data and in any case encoded string 
     * should not be null-terminated. 
     *  
     * You have two options: 
     *    - provide a "raw" buffer and its length
     *    - provide NULL-terminated string and leave the p_length
     *      parameter unspecified (in this case strlen() will be
     *      used to determine encoded string length)
     *
     * @param[in] p_data   - pointer to the beginning of string data
     * @param[in] p_length - string length (optional)
     * @return RC_SUCCESS or RC_FAIL
     */
    int setString(const char * p_data, uint16_t p_length = 0);


    // ===========================
    // Vendor-Specific attribute
    // ===========================

    /// Get vendor ID of Vendor-Specific attribute
    /**
     * @return vendor ID numeric value in host order format
     */
    uint32_t getVendorId(void);
    
    /// Set vendor ID of Vendor-Specific attribute
    /**
     * @param[in] p_vendorId - vendor ID numeric value in host order format
     * @return RC_SUCCESS or RC_FAIL
     */
    int setVendorId(uint32_t p_vendorId);

    /// Get "raw" string data of Vendor-Specific attribute
    /**
     * "Raw" string data of Vendor-Specific attribute typically 
     * contains Vendor Type, Vendor Length and Attribute-specific 
     * data. Therefore in most cases you should use getVendorType(),
     * getVendorLength() and getVendorNumber() instead of this 
     * method. 
     *  
     * Note that string data may contain both readable characters and non-readable
     * binary data. In any case string will not be null-terminated, 
     * hence yous should use returned p_length value to properly
     * operate on it. 
     *
     * @param[out] p_data   - pointer to the beginning of string data
     * @param[out] p_length - string length
     * @return RC_SUCCESS or RC_FAIL
     */
    int getVendorRawString(const char * & p_data, uint16_t & p_length);
    
    /// Set "raw" string data of Vendor-Specific attribute
    /**
     * "Raw" string data of Vendor-Specific attribute typically 
     * contains Vendor Type, Vendor Length and Attribute-specific 
     * data. Therefore in most cases you should use setVendorType(),
     * setVendorLength() and setVendorNumber() instead of this 
     * method. 
     *  
     * Note that string data may contain both readable characters 
     * and non-readable binary data and in any case encoded string 
     * should not be null-terminated. 
     *  
     * You have two options: 
     *    - provide a "raw" buffer and its length
     *    - provide NULL-terminated string and leave the p_length
     *      parameter unspecified (in this case strlen() will be
     *      used to determine encoded string length)
     *
     * @param[in] p_data   - pointer to the beginning of string data
     * @param[in] p_length - string length (optional)
     * @return RC_SUCCESS or RC_FAIL
     */
    int setVendorRawString(const char * p_data, uint16_t p_length = 0);


    /// Get vendor type of Vendor-Specific attribute
    /**
     * @return vendor type
     */
	unsigned char getVendorType();

    /// Set vendor type of Vendor-Specific attribute
    /**
     * @param[in] p_value - vendor type value
     * @return RC_SUCCESS or RC_FAIL
     */
	int setVendorType(unsigned char p_value);


    /// Get vendor length of Vendor-Specific attribute
    /**
     * @return vendor length
     */
	unsigned char getVendorLength();

    /// Set vendor length of Vendor-Specific attribute
    /**
     * @param[in] p_length - vendor length value
     * @return RC_SUCCESS or RC_FAIL
     */
	int setVendorLength(unsigned char p_length);


    /// Get value of the numeric Vendor-Specific attribute
    /**
     * @return value of numeric attribute in host order format
     */
	uint32_t getVendorNumber();
    
    /// Set value of the numeric Vendor-Specific attribute
    /**
     * @param[in] p_value - numeric value in host order format
     * @return RC_SUCCESS if attribute is successfully encode; RC_FAIL otherwise
     */
	int setVendorNumber(uint32_t p_value);


    /// Get value of the IP address Vendor-Specific attribute
    /**
     * @return value of IP address attribute
     */
	struct in_addr getVendorIPAddress();   

    /// Set value of the IP address Vendor-Specific attribute
    /**
     * @param[in] p_value - IP address
     * @return RC_SUCCESS if attribute is successfully encode; RC_FAIL otherwise
     */
	int setVendorIPAddress(struct in_addr p_address);

    /// Set a complete Vendor-Specific attribute (Vendor-Id, Vendor-Type, Vendor-Length and data)
    /// in one call. Example: Mikrotik-Rate-Limit: vendorId 14988, vendorType 8, "10M/10M"
    int setVendorAttribute(uint32_t p_vendorId, unsigned char p_vendorType, const void * p_data, uint16_t p_length);


    /// Get value of the string Vendor-Specific attribute
    /**
     * Note that string data may contain both readable characters 
     * and non-readable binary data. In any case string will not be 
     * null-terminated, hence you should use returned p_length value 
     * to properly operate on it. 
     *
     * @param[out] p_data   - pointer to the beginning of string data
     * @param[out] p_length - string length
     * @return RC_SUCCESS or RC_FAIL
     */
	int getVendorString(const char * & p_data, uint16_t & p_length);
    
    /// Set value of the string Vendor-Specific attribute
    /**
     * Note that string data may contain both readable characters and non-readable
     * binary data. In any case string should not be null-terminated.
     *
     * Note that string data may contain both readable characters 
     * and non-readable binary data and in any case encoded string 
     * should not be null-terminated. 
     *  
     * You have two options: 
     *    - provide a "raw" buffer and its length
     *    - provide NULL-terminated string and leave the p_length
     *      parameter unspecified (in this case strlen() will be
     *      used to determine encoded string length)
     *
     * @param[in] p_data   - pointer to the beginning of string data
     * @param[in] p_length - string length (optional)
     * @return RC_SUCCESS or RC_FAIL
     */
	int setVendorString(const char * p_data, uint16_t p_length = 0);


    // ===========================
    // User-Password attribute
    // ===========================
    
    /// Get string data of User-Password attribute
    /**
     * Password is decoded from the packet using secret key and presented in 
     * it's "original" form.
     *  
     * Note that password may contain both readable characters and 
     * non-readable binary data. In any case string will not be 
     * null-terminated, hence you should use returned p_length value
     * to properly operate on it. 
     *
     * @param[in] p_data   - pointer to local buffer allocated by application
     *                        where the decoded password will be stored
     * @param[out] p_length - string length
     * @param[in] p_secret - secret key (if NULL, stack's secret key is taken)
     * @return RC_SUCCESS or RC_FAIL
     *
     * IMPORTANT: allocate the buffer of size  D_USER_PASSWORD_MAX_LENGTH 
     *            for storing decoded password data and pass it as
     *            p_data
     */
    int getUserPassword(char * p_data, uint16_t & p_length, 
                        RadiusSecret * p_secret = NULL);
    
    /// Set string data of User-Password attribute
    /**
     * Password is encoded into the packet using secret key. 
     * The actual encoding is performed when packet is transmitted 
     * to the network (using the secret key of current connection) -
     * therefore if you "dump" packet beforehand you won't see 
     * any data encoded. 
     *  
     * Note that the password may contain both readable characters 
     * and non-readable binary data. In any case encoded string 
     * should not be null-terminated. 
     *  
     * You have two options: 
     *    - provide a "raw" buffer and its length
     *    - provide NULL-terminated string and leave the p_length
     *      parameter unspecified (in this case strlen() will be
     *      used to determine encoded password length)
     *  
     * @param[in] p_data   - pointer to the beginning of string data
     * @param[in] p_length - string length
     * @return RC_SUCCESS or RC_FAIL
     */
    int setUserPassword(const char * p_data, uint16_t p_length = 0);

    // Encode raw data of User-Password attribute
    /*
     * We need this function in order to re-encode User-Password attribute with new secret key
     * when packet is retransmitted through new connection; application should not use this API.
     */
    int encodeUserPassword(const unsigned char * p_data, uint16_t p_length);


    // ===========================
    // Old-Password attribute
    // ===========================

    /// Get string data of Old-Password attribute
    /**
     * Password is decoded from the packet using secret key and presented in 
     * it's "original" form.
     *  
     * Note that string data may contain both readable characters 
     * and non-readable binary data. In any case string will not be 
     * null-terminated, hence you should use returned p_length value 
     * to properly operate on it. 
     *
     * @param[in] p_data   - pointer to local buffer allocated by application
     *                        where the decoded password will be stored
     * @param[out] p_length - string length
     * @param[in] p_secret - secret key (if NULL, stack's secret key is taken)
     * @return RC_SUCCESS or RC_FAIL
     *
     * IMPORTANT: allocate the buffer of size D_USER_PASSWORD_MAX_LENGTH 
     *            for storing decoded password data and pass it as
     *            p_data
     */
    int getOldPassword(char * p_data, uint16_t & p_length, 
                        RadiusSecret * p_secret = NULL);

    /// Set string data of Old-Password attribute
    /**
     * Password is encoded into the packet using secret key.
     * The actual encoding is performed when packet is transmitted 
     * to the network (using the secret key of current connection) -
     * therefore if you "dump" packet beforehand you won't see 
     * any data encoded. 
     * 
     * The application must add User-Password attribute prior to 
     * adding Old-Password, since encrypted User-Password data is 
     * used instead of shared authenticator for encoding 
     *  
     * Note that the password may contain both readable characters 
     * and non-readable binary data. In any case encoded string 
     * should not be null-terminated. 
     *  
     * You have two options: 
     *    - provide a "raw" buffer and its length
     *    - provide NULL-terminated string and leave the p_length
     *      parameter unspecified (in this case strlen() will be
     *      used to determine encoded password length)
     *
     * @param[in] p_data   - pointer to the beginning of string data
     * @param[in] p_length - string length
     * @return RC_SUCCESS or RC_FAIL
     */
    int setOldPassword(const char * p_data, uint16_t p_length = 0);

    // Encode raw data of Old-Password attribute
    /*
     * We need this function in order to re-encode User-Password attribute with new secret key
     * when packet is retransmitted through new connection; application should not use this API.
     */
    int encodeOldPassword(const unsigned char * p_data, uint16_t p_length);


    // ===========================
    // CHAP-Password attribute
    // ===========================

    /// Get CHAP identifier of CHAP-Password attribute
    /**
     * @return CHAP identifier
     */
    unsigned char getChapIdentifier(void);
    
    /// Set vendor ID of CHAP-Password attribute
    /**
     * @param[in] p_chapIdentifier - CHAP identifier value
     * @return RC_SUCCESS or RC_FAIL
     */
    int setChapIdentifier(unsigned char p_chapId);

    /// Get string data of CHAP-Password attribute
    /**
     * Note that string data may contain both readable characters 
     * and non-readable binary data. In any case string will not be 
     * null-terminated, hence you should use returned p_length value 
     * to properly operate on it. 
     *
     * @param[out] p_data   - pointer to the beginning of string data
     * @param[out] p_length - string length
     * @return RC_SUCCESS or RC_FAIL
     */
    int getChapString(const char * & p_data, uint16_t & p_length);
    
    /// Set string data of CHAP-Password attribute
    /**
     * Note that string data may contain both readable characters and non-readable
     * binary data. In any case string should not be null-terminated.
     *
     * You have two options: 
     *    - provide a "raw" buffer and its length
     *    - provide NULL-terminated string and leave the p_length
     *      parameter unspecified (in this case strlen() will be
     *      used to determine encoded password length)
     *
     * @param[in] p_data   - pointer to the beginning of string data
     * @param[in] p_length - string length
     * @return RC_SUCCESS or RC_FAIL
     */
    int setChapString(const char * p_data, uint16_t p_length = 0);



private:

    // attribute is valid, has at least p_minLength bytes (header included) and fits into the packet
    bool fits(uint8_t p_minLength);

    // reserve room for a NEW attribute at the end of the packet / undo it
    int reserve(uint16_t p_length);
    void release(void);

    // Get pointer to the attribute raw data
    unsigned char * getRawData(void);

    // Types of attribute data
    enum AttributeFormat_e
    {
        E_ATTR_FORMAT_INTEGER,
        E_ATTR_FORMAT_IP_ADDRESS,
        E_ATTR_FORMAT_STRING,
        E_ATTR_FORMAT_VENDOR_SPECIFIC,
        E_ATTR_FORMAT_USER_PASSWORD,
        E_ATTR_FORMAT_CHAP_PASSWORD
    };

    // Dump attribute in readable text format to the STDOUT
    /**
     * @param[in] p_format - attribute format; 
     */
    void dump(AttributeFormat_e p_format);

    //////////////////////////////////////////////////////////////////////

    // Pointer to the RADIUS packet that this attribute belongs to
    RadiusPacket * m_packet;

    // Offset of the attribute inside the RADIUS packet
    uint16_t m_offset;
};

#endif // _RADIUSATTRIBUTE_H__

