/*
 * This source file is part of the ace-radius-linux library.  This code was
 * written by Alex Agranov in 2004-2009, and is covered by the BSD open source
 * license. Refer to the accompanying documentation for details on usage and
 * license.
 */

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include <string.h>

#include "RadiusSecret.h"


// ---------------------------
// constructor
// ---------------------------
RadiusSecret::RadiusSecret() :
    m_secretLength(0)
{
    memset(m_secret, 0, sizeof(m_secret));
}


// ---------------------------
// constructor
// ---------------------------
RadiusSecret::RadiusSecret(const char * p_string) :
    m_secretLength(0)
{
    memset(m_secret, 0, sizeof(m_secret));

    if (p_string != NULL)
        setSecret(p_string, (uint16_t)strnlen(p_string, D_SECRET_MAX_LENGTH + 1));
}


// ---------------------------
// Copy constructor
// ---------------------------
RadiusSecret::RadiusSecret(const RadiusSecret & other) :
    m_secretLength(other.m_secretLength)
{
    memcpy(m_secret, other.m_secret, sizeof(m_secret));
}


// ---------------------------
// Assignment
// ---------------------------
RadiusSecret & RadiusSecret::operator=(const RadiusSecret & other)
{
    if (this != &other)
    {
        m_secretLength = other.m_secretLength;
        memcpy(m_secret, other.m_secret, sizeof(m_secret));
    }
    return *this;
}


// ---------------------------
// Get secret key
// ---------------------------
int RadiusSecret::getSecret(const unsigned char * & p_data, uint16_t & p_length) const
{
    // out parameters are always written, so callers never use uninitialized values
    p_data = m_secret;
    p_length = m_secretLength;

    if (m_secretLength == 0)
        return RC_FAIL;

    return RC_SUCCESS;
}


// ---------------------------
// Set secret key
// ---------------------------
int RadiusSecret::setSecret(const char * p_data, uint16_t p_length)
{
    if (!p_data || p_length == 0 || p_length > D_SECRET_MAX_LENGTH)
        return RC_FAIL;

    memset(m_secret, 0, sizeof(m_secret));
    memcpy(m_secret, p_data, p_length);
    m_secretLength = p_length;
    return RC_SUCCESS;
}

