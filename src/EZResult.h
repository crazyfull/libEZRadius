#ifndef EZRESULT_H
#define EZRESULT_H

enum class EZResult {
    NONE = 0,           // nothing sent yet / request in progress
    OK,                 // a valid response was received (see GetResponseType())
    TIMEOUT,            // no valid response after RetryCount attempts
    DNS_FAILED,         // the host name could not be resolved
    SEND_FAILED,        // socket / connection error
    CANCELED            // Cancel() was called
};

#endif // EZRESULT_H
