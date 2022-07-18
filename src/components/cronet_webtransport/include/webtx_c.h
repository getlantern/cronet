#ifndef COMPONENTS_CRONET_WEBTRANSPORT_WEBTX_C_H_
#define COMPONENTS_CRONET_WEBTRANSPORT_WEBTX_C_H_

#if defined(WIN32)
#define CRONET_WEBTRANSPORT_SUPPORT_EXPORT __declspec(dllexport)
#else
#define CRONET_WEBTRANSPORT_SUPPORT_EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef struct WebTx_Client WebTx_Client;
typedef struct WebTx_Client* WebTx_ClientPtr;
typedef struct WebTx_Stream WebTx_Stream;
typedef struct WebTx_Stream* WebTx_StreamPtr;

typedef enum WebTx_ERROR {
    WebTx_ERROR_NONE = 0,
    WebTx_ERROR_OTHER = 1,
    WebTx_ERROR_EOF = 2,
    WebTx_ERROR_HOSTNAME_NOT_RESOLVED = 3,
    WebTx_ERROR_INTERNET_DISCONNECTED = 4,
    WebTx_ERROR_NETWORK_CHANGED = 5,
    WebTx_ERROR_TIMED_OUT = 6,
    WebTx_ERROR_CONNECTION_CLOSED = 7,
    WebTx_ERROR_CONNECTION_REFUSED = 8,
    WebTx_ERROR_CONNECTION_RESET = 9,
    WebTx_ERROR_ADDRESS_UNREACHABLE = 10,
    WebTx_ERROR_QUIC_PROTOCOL_FAILED = 11,
    WebTx_ERROR_QUIC_TOO_MANY_STREAMS = 12,
} WebTx_ERROR;

typedef struct WebTx_ErrorDetails {
    WebTx_ERROR err;
    int net_err;
    int quic_err;
    const char *details;
} WebTx_ErrorDetails;

typedef struct WebTx_OpenStreamResult {
    WebTx_StreamPtr stream;
    WebTx_ERROR err;
} WebTx_OpenStreamResult;

typedef struct WebTx_IOResult {
    uint64_t len;
    WebTx_ERROR err;
} WebTx_IOResult;


typedef void (*WebTx_ClientCallback_OnConnectedFunc)(void *callback_data);
typedef void (*WebTx_ClientCallback_OnConnectionFailedFunc)(void *callback_data, WebTx_ErrorDetails err);
typedef void (*WebTx_ClientCallback_OnClosedFunc)(void *callback_data, uint32_t code, const char *reason);
typedef void (*WebTx_ClientCallback_OnErrorFunc)(void *callback_data, WebTx_ErrorDetails err);
typedef void (*WebTx_ClientCallback_OnCanCreateNewOutgoingBidirectionalStreamFunc)(void *callback_data);
typedef void (*WebTx_ClientCallback_OnIncomingBidirectionalStreamAvailableFunc)(void *callback_data);
typedef void (*WebTx_ClientCallback_OnIncomingUnidirectionalStreamAvailableFunc)(void *callback_data);
typedef void (*WebTx_ClientCallback_OnCanCreateNewOutgoingUnidirectionalStreamFunc)(void *callback_data);

typedef struct WebTx_ClientVisitor {
    void *callback_data;
    WebTx_ClientCallback_OnConnectedFunc OnConnected;
    WebTx_ClientCallback_OnConnectionFailedFunc OnConnectionFailed;
    WebTx_ClientCallback_OnClosedFunc OnClosed;
    WebTx_ClientCallback_OnErrorFunc OnError;
    WebTx_ClientCallback_OnCanCreateNewOutgoingBidirectionalStreamFunc OnCanCreateNewOutgoingBidirectionalStream;
    WebTx_ClientCallback_OnIncomingBidirectionalStreamAvailableFunc OnIncomingBidirectionalStreamAvailable;
    WebTx_ClientCallback_OnIncomingUnidirectionalStreamAvailableFunc OnIncomingUnidirectionalStreamAvailable;
    WebTx_ClientCallback_OnCanCreateNewOutgoingUnidirectionalStreamFunc OnCanCreateNewOutgoingUnidirectionalStream;

} WebTx_ClientVisitor;

extern const WebTx_ClientVisitor WebTx_ClientVisitor_Empty;

typedef void (*WebTx_StreamCallback_OnCanReadFunc)(void *callback_data);
typedef void (*WebTx_StreamCallback_OnCanWriteFunc)(void *callback_data);
typedef void (*WebTx_StreamCallback_OnResetStreamReceivedFunc)(void *callback_data, uint8_t code);
typedef void (*WebTx_StreamCallback_OnStopSendingReceivedFunc)(void *callback_data, uint8_t code);
typedef void (*WebTx_StreamCallback_OnWriteSideInDataRecvdStateFunc)(void *callback_data);


typedef struct WebTx_StreamVisitor {
    void *callback_data;
    WebTx_StreamCallback_OnCanReadFunc OnCanRead;
    WebTx_StreamCallback_OnCanWriteFunc OnCanWrite;
    WebTx_StreamCallback_OnResetStreamReceivedFunc OnResetStreamReceived;
    WebTx_StreamCallback_OnStopSendingReceivedFunc OnStopSendingReceived;
    WebTx_StreamCallback_OnWriteSideInDataRecvdStateFunc OnWriteSideInDataRecvdState;

} WebTx_StreamVisitor;

extern const WebTx_StreamVisitor WebTx_StreamVisitor_Empty;

typedef struct WebTx_ClientOptions WebTx_ClientOptions;
typedef WebTx_ClientOptions * WebTx_ClientOptionsPtr;

WebTx_ClientOptionsPtr WebTx_ClientOptions_Create();
void WebTx_ClientOptions_SetVisitor(WebTx_ClientOptionsPtr options, WebTx_ClientVisitor v); 
void WebTx_ClientOptions_SetAddr(WebTx_ClientOptionsPtr options, const char *addr);
void WebTx_ClientOptions_SetPath(WebTx_ClientOptionsPtr options, const char *path);
void WebTx_ClientOptions_SetCert(WebTx_ClientOptionsPtr options, const uint8_t*der, uint64_t len);
void WebTx_ClientOptions_SetInsecureSkipVerify(WebTx_ClientOptionsPtr options, uint8_t shouldSkip);
void WebTx_ClientOptions_Destroy(WebTx_ClientOptionsPtr options);

WebTx_ClientPtr WebTx_Client_Create(WebTx_ClientOptionsPtr);
WebTx_ERROR WebTx_Client_Connect(WebTx_ClientPtr);
WebTx_ERROR WebTx_Client_Close(WebTx_ClientPtr);
WebTx_ERROR WebTx_Client_Destroy(WebTx_ClientPtr);

WebTx_OpenStreamResult WebTx_Client_OpenOutgoingBidirectionalStream(WebTx_ClientPtr);

WebTx_IOResult WebTx_Stream_Read(WebTx_StreamPtr, char* buffer, uint64_t buffer_size);
WebTx_IOResult WebTx_Stream_Write(WebTx_StreamPtr, char *buffer, uint64_t len);
WebTx_ERROR WebTx_Stream_SendFin(WebTx_StreamPtr);
void WebTx_Stream_ResetWithUserCode(WebTx_StreamPtr, uint8_t error);
int WebTx_Stream_ReadableBytes(WebTx_StreamPtr);
int WebTx_Stream_CanWrite(WebTx_StreamPtr);
void WebTx_Stream_SetVisitor(WebTx_StreamPtr, WebTx_StreamVisitor v);
void WebTx_Stream_Destroy(WebTx_StreamPtr);

void *WebTx_Create_PinnedCertVerifier(const uint8_t*der, uint64_t len, uint8_t insecureSkipVerify);

#ifdef __cplusplus
}
#endif


#endif // _NET_TOOLS_CROW_CROW_H_
