#include "EZTransport.h"

EZStreamFramer::Result EZStreamFramer::next(std::string &packet)
{
    const size_t avail = m_buf.size() - m_pos;
    if(avail < 4)
        return NEED_MORE;
    const size_t len = ((size_t)(uint8_t)m_buf[m_pos + 2] << 8) | (uint8_t)m_buf[m_pos + 3];
    if(len < MIN_PACKET || len > MAX_PACKET)
        return INVALID;
    if(avail < len)
        return NEED_MORE;
    packet.assign(m_buf, m_pos, len);
    m_pos += len;
    if(m_pos == m_buf.size()){
        m_buf.clear();
        m_pos = 0;
    }else if(m_pos > 8192){         // do not keep consumed bytes around
        m_buf.erase(0, m_pos);
        m_pos = 0;
    }
    return PACKET;
}
