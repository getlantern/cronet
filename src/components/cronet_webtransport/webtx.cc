

#include "components/cronet_webtransport/cert_verify_proc_pinned.h"
#include "components/cronet_webtransport/include/webtx_c.h"

#include "base/at_exit.h"
#include "base/strings/strcat.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/thread_pool/thread_pool_instance.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/thread.h"
#include "net/base/network_isolation_key.h"
#include "net/cert/asn1_util.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/cert_verify_proc.h"
#include "net/cert/multi_threaded_cert_verifier.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "net/quic/web_transport_client.h"
#include "net/quic/web_transport_error.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "url/gurl.h"

const WebTx_ClientVisitor WebTx_ClientVisitor_Empty = {0};
const WebTx_StreamVisitor WebTx_StreamVisitor_Empty = {0};

class WebTx_Context {
public:
    WebTx_Context();
    ~WebTx_Context();

    WebTx_Context(const WebTx_Context&) = delete;
    WebTx_Context& operator=(const WebTx_Context&) = delete;

    scoped_refptr<base::SingleThreadTaskRunner> GetNetworkTaskRunner();

private:
    std::unique_ptr<base::Thread> network_thread_;
    scoped_refptr<base::SingleThreadTaskRunner> network_task_runner_;
};


WebTx_Context::WebTx_Context() {
    network_thread_ = std::make_unique<base::Thread>("network");
    base::Thread::Options options;
    options.message_pump_type = base::MessagePumpType::IO;
    network_thread_->StartWithOptions(std::move(options));
    network_task_runner_ = network_thread_->task_runner();
}

WebTx_Context::~WebTx_Context() {}

scoped_refptr<base::SingleThreadTaskRunner> WebTx_Context::GetNetworkTaskRunner() {
    return network_task_runner_;
}

std::unique_ptr<WebTx_Context> _WebTx_Initialize() {
    static base::AtExitManager at_exit_manager;
    base::ThreadPoolInstance::CreateAndStartWithDefaultParams("crow");
    return std::make_unique<WebTx_Context>();
}

std::shared_ptr<WebTx_Context> WebTx_EnsureInitialized() {
    static std::shared_ptr<WebTx_Context> ctx = _WebTx_Initialize();
    return ctx;
}

WebTx_ERROR WebTx_NetErrorToWebTxError(int net_error) {
  switch (net_error) {
    case net::ERR_NAME_NOT_RESOLVED:
        return WebTx_ERROR_HOSTNAME_NOT_RESOLVED;
    case net::ERR_INTERNET_DISCONNECTED:
        return WebTx_ERROR_INTERNET_DISCONNECTED;
    case net::ERR_NETWORK_CHANGED:
        return WebTx_ERROR_NETWORK_CHANGED;
    case net::ERR_TIMED_OUT:
        return WebTx_ERROR_TIMED_OUT;
    case net::ERR_CONNECTION_CLOSED:
        return WebTx_ERROR_CONNECTION_CLOSED;
    case net::ERR_CONNECTION_TIMED_OUT:
        return WebTx_ERROR_TIMED_OUT;
    case net::ERR_CONNECTION_REFUSED:
        return WebTx_ERROR_CONNECTION_REFUSED;
    case net::ERR_CONNECTION_RESET:
        return WebTx_ERROR_CONNECTION_RESET;
    case net::ERR_ADDRESS_UNREACHABLE:
        return WebTx_ERROR_ADDRESS_UNREACHABLE;
    case net::ERR_QUIC_PROTOCOL_ERROR:
        return WebTx_ERROR_QUIC_PROTOCOL_FAILED;
    default:
        return WebTx_ERROR_OTHER;
  }
}

WebTx_ErrorDetails WebTx_MakeErrorDetails(const net::WebTransportError& error) {
    return {
        .err = WebTx_NetErrorToWebTxError(error.net_error),
        .net_err = error.net_error,
        .quic_err = error.quic_error,
        .details = error.details.c_str(),
    };
}

class _WebTx_StreamVisitor : public quic::WebTransportStreamVisitor {
public:
    _WebTx_StreamVisitor(WebTx_StreamVisitor v): visitor_(v) {}
    ~_WebTx_StreamVisitor() override {}

    // Called whenever the stream has readable data available.
    void OnCanRead() override {
        if (visitor_.OnCanRead) {
            visitor_.OnCanRead(visitor_.callback_data);
        }
    }

    // Called whenever the stream is not write-blocked and can accept new data.
    void OnCanWrite() override {
        if (visitor_.OnCanWrite) {
            visitor_.OnCanWrite(visitor_.callback_data);
        }
    }

    // Called when RESET_STREAM is received for the stream.
    void OnResetStreamReceived(quic::WebTransportStreamError error) override {
        if (visitor_.OnResetStreamReceived) {
            visitor_.OnResetStreamReceived(visitor_.callback_data, uint8_t(error));
        }
    }

    // Called when STOP_SENDING is received for the stream.
    void OnStopSendingReceived(quic::WebTransportStreamError error) override {
        if (visitor_.OnStopSendingReceived) {
            visitor_.OnStopSendingReceived(visitor_.callback_data, uint8_t(error));
        }
    }

    // Called when the write side of the stream is closed and all of the data sent
    // has been acknowledged ("Data Recvd" state of RFC 9000).
    void OnWriteSideInDataRecvdState() override {
        if (visitor_.OnWriteSideInDataRecvdState) {
            visitor_.OnWriteSideInDataRecvdState(visitor_.callback_data);
        }
    }
  
private:
    WebTx_StreamVisitor visitor_;
};



class _WebTx_ClientVisitor : public net::WebTransportClientVisitor {
public:
    _WebTx_ClientVisitor(WebTx_ClientVisitor v): visitor_(v) {}
    ~_WebTx_ClientVisitor() override {}

    // State change notifiers.
    // CONNECTING -> CONNECTED
    void OnConnected(scoped_refptr<net::HttpResponseHeaders> response_headers) override {
        if (visitor_.OnConnected) {
            visitor_.OnConnected(visitor_.callback_data);
        }
    }
    // CONNECTING -> FAILED
    void OnConnectionFailed(const net::WebTransportError& error) override {
        if (visitor_.OnConnectionFailed) {
            WebTx_ErrorDetails err = WebTx_MakeErrorDetails(error);
            visitor_.OnConnectionFailed(visitor_.callback_data, err);
        }
    }
    // CONNECTED -> CLOSED
    void OnClosed(const absl::optional<net::WebTransportCloseInfo>& close_info) override {
        if (visitor_.OnClosed) {
            visitor_.OnClosed(visitor_.callback_data, close_info->code, close_info->reason.c_str());
        }
    }
    // CONNECTED -> FAILED
    void OnError(const net::WebTransportError& error) override {
        if (visitor_.OnError) {
            WebTx_ErrorDetails err = WebTx_MakeErrorDetails(error);            
            visitor_.OnError(visitor_.callback_data, err);
        }
    }

    void OnCanCreateNewOutgoingBidirectionalStream() override {
        if (visitor_.OnCanCreateNewOutgoingBidirectionalStream) {
            visitor_.OnCanCreateNewOutgoingBidirectionalStream(visitor_.callback_data);
        }
    }
    
    void OnIncomingBidirectionalStreamAvailable() override {
        if (visitor_.OnIncomingBidirectionalStreamAvailable) {
            visitor_.OnIncomingBidirectionalStreamAvailable(visitor_.callback_data);
        }
    }

    void OnIncomingUnidirectionalStreamAvailable() override {
        if (visitor_.OnIncomingUnidirectionalStreamAvailable) {
            visitor_.OnIncomingUnidirectionalStreamAvailable(visitor_.callback_data);
        }
    }

    void OnCanCreateNewOutgoingUnidirectionalStream() override {
        if (visitor_.OnCanCreateNewOutgoingUnidirectionalStream) {
            visitor_.OnCanCreateNewOutgoingUnidirectionalStream(visitor_.callback_data);
        }
    }

    void OnDatagramReceived(base::StringPiece datagram) override {}
    void OnDatagramProcessed(absl::optional<quic::MessageStatus> status) override {}
private:
    WebTx_ClientVisitor visitor_;
};

struct WebTx_Stream {
    WebTx_Stream(quic::WebTransportStream *stream);
    WebTx_Stream(const WebTx_Stream&) = delete;
    WebTx_Stream& operator=(const WebTx_Stream&) = delete;
    virtual ~WebTx_Stream() = default;

    WebTx_IOResult Read(char* buffer, uint64_t buffer_size);
    WebTx_IOResult Write(char *buffer, uint64_t len);
    WebTx_ERROR    SendFin();
    void ResetWithUserCode(uint8_t error);
	int ReadableBytes();
	int CanWrite();
	void SetVisitor(WebTx_StreamVisitor v);

private:
    quic::WebTransportStream *stream_ = nullptr;
};


WebTx_Stream::WebTx_Stream(quic::WebTransportStream *stream): 
    stream_(stream) {}


WebTx_IOResult WebTx_Stream::Read(char* buffer, uint64_t buffer_size) {
    quic::WebTransportStream::ReadResult rr = stream_->Read(buffer, buffer_size);
    return WebTx_IOResult{
        .len = rr.bytes_read,
        .err = rr.fin ? WebTx_ERROR_EOF : WebTx_ERROR_NONE,
    };
}

WebTx_IOResult WebTx_Stream::Write(char *buffer, uint64_t len) {
    if (stream_->Write(absl::string_view(buffer, len))) {
        return WebTx_IOResult{
            .len = len,
            .err = WebTx_ERROR_NONE,
        };
    } else {
        return WebTx_IOResult{
            .len = 0,
            .err = WebTx_ERROR_QUIC_PROTOCOL_FAILED,
        };
    }
}

WebTx_ERROR WebTx_Stream::SendFin() {
    return stream_->SendFin() ? WebTx_ERROR_NONE : WebTx_ERROR_QUIC_PROTOCOL_FAILED;
}

void WebTx_Stream::ResetWithUserCode(uint8_t error) {
    stream_->ResetWithUserCode((quic::WebTransportStreamError)error);
}

int WebTx_Stream::ReadableBytes() {
	return stream_->ReadableBytes();
}

int WebTx_Stream::CanWrite() {
	return stream_->CanWrite();
}

void WebTx_Stream::SetVisitor(WebTx_StreamVisitor v) {
    auto visitor = std::make_unique<_WebTx_StreamVisitor>(v);
	stream_->SetVisitor(std::move(visitor));
}


WebTx_IOResult WebTx_Stream_Read(WebTx_StreamPtr self, char* buffer, uint64_t buffer_size) {
    DCHECK(self);
    return self->Read(buffer, buffer_size);
}

WebTx_IOResult WebTx_Stream_Write(WebTx_StreamPtr self, char *buffer, uint64_t len) {
    DCHECK(self);
    return self->Write(buffer, len);
}

WebTx_ERROR WebTx_Stream_SendFin(WebTx_StreamPtr self) {
    DCHECK(self);
    return self->SendFin();
}

void WebTx_Stream_ResetWithUserCode(WebTx_StreamPtr self, uint8_t error) {
    DCHECK(self);
    return self->ResetWithUserCode(error);
}

int WebTx_Stream_ReadableBytes(WebTx_StreamPtr self) {
	DCHECK(self);
	return self->ReadableBytes();
}

int WebTx_Stream_CanWrite(WebTx_StreamPtr self) {
	DCHECK(self);
	return self->CanWrite();
}

void WebTx_Stream_SetVisitor(WebTx_StreamPtr self, WebTx_StreamVisitor v) {
	DCHECK(self);
	self->SetVisitor(v);
}

void WebTx_Stream_Destroy(WebTx_StreamPtr self) {
    DCHECK(self);
    delete self;
}

struct WebTx_ClientOptions {
    WebTx_ClientOptions();
    WebTx_ClientOptions(const WebTx_ClientOptions&) = delete;
    WebTx_ClientOptions& operator=(const WebTx_ClientOptions&) = delete;
    ~WebTx_ClientOptions();

    void SetVisitor(WebTx_ClientVisitor v); 
    void SetAddr(std::string addr);
    void SetPath(std::string path);
    void SetCert(scoped_refptr<net::X509Certificate> cert);
    void SetInsecureSkipVerify(bool shouldSkip);

    WebTx_ClientVisitor visitor;
    std::string addr;
    std::string path;
    scoped_refptr<net::X509Certificate> cert;
    bool insecureSkipVerify;
};

WebTx_ClientOptions::WebTx_ClientOptions() {}
WebTx_ClientOptions::~WebTx_ClientOptions() {}

void WebTx_ClientOptions::SetVisitor(WebTx_ClientVisitor v) {
    this->visitor = v;
}

void WebTx_ClientOptions::SetAddr(std::string a) {
    this->addr = a;
}

void WebTx_ClientOptions::SetPath(std::string p) {
    this->path = p;
}

void WebTx_ClientOptions::SetCert(scoped_refptr<net::X509Certificate> c) {
    this->cert = c;
}

void WebTx_ClientOptions::SetInsecureSkipVerify(bool shouldSkip) {
    this->insecureSkipVerify = shouldSkip;
}

WebTx_ClientOptionsPtr WebTx_ClientOptions_Create() {
    return new(WebTx_ClientOptions);
}

void WebTx_ClientOptions_SetVisitor(WebTx_ClientOptionsPtr self, WebTx_ClientVisitor v) {
    self->SetVisitor(v);
}

void WebTx_ClientOptions_SetAddr(WebTx_ClientOptionsPtr self, const char *addr) {
    self->SetAddr(addr);
}
void WebTx_ClientOptions_SetPath(WebTx_ClientOptionsPtr self, const char *path) {
    self->SetPath(path);
}

void WebTx_ClientOptions_SetCert(WebTx_ClientOptionsPtr self, const uint8_t*derBytes, uint64_t len) {
    auto cert = net::X509Certificate::CreateFromBytes(base::make_span(derBytes, len));
}

void WebTx_ClientOptions_SetInsecureSkipVerify(WebTx_ClientOptionsPtr self, uint8_t shouldSkip) {
    self->SetInsecureSkipVerify(shouldSkip != 0);
}

void WebTx_ClientOptions_Destroy(WebTx_ClientOptionsPtr options) {
    delete options;
}

struct WebTx_Client {
  WebTx_Client(std::unique_ptr<net::WebTransportClient> client, std::unique_ptr<net::URLRequestContext> context, std::unique_ptr<_WebTx_ClientVisitor> visitor);
  WebTx_Client(const WebTx_Client&) = delete;
  WebTx_Client& operator=(const WebTx_Client&) = delete;
  virtual ~WebTx_Client() = default;

  WebTx_ERROR Connect();
  WebTx_ERROR Close();

  WebTx_OpenStreamResult OpenOutgoingBidirectionalStream();

private:
    std::unique_ptr<net::WebTransportClient> client_ = nullptr;
    std::unique_ptr<net::URLRequestContext> context_ = nullptr;
    std::unique_ptr<_WebTx_ClientVisitor> visitor_ = nullptr;
};

WebTx_Client::WebTx_Client(std::unique_ptr<net::WebTransportClient> client, std::unique_ptr<net::URLRequestContext> context, std::unique_ptr<_WebTx_ClientVisitor> visitor):
    client_(std::move(client)), context_(std::move(context)), visitor_(std::move(visitor)) {}


WebTx_ERROR WebTx_Client::Connect() {
    client_->Connect();
    return WebTx_ERROR_NONE;
}

WebTx_OpenStreamResult WebTx_Client::OpenOutgoingBidirectionalStream() {
    quic::WebTransportSession *session = client_->session();
    if (session == nullptr) {
        return WebTx_OpenStreamResult{
            .stream = nullptr,
            .err = WebTx_ERROR_CONNECTION_CLOSED,
        };
    }

    if (!session->CanOpenNextOutgoingBidirectionalStream()) {
        return WebTx_OpenStreamResult{
            .stream = nullptr,
            .err = WebTx_ERROR_QUIC_TOO_MANY_STREAMS,
        };
    }

    quic::WebTransportStream *wts = session->OpenOutgoingBidirectionalStream();
    if (wts == nullptr) {
        return WebTx_OpenStreamResult{
            .stream = nullptr,
            .err = WebTx_ERROR_QUIC_PROTOCOL_FAILED,
        };
    }

    return WebTx_OpenStreamResult{
        .stream = new WebTx_Stream(wts),
        .err = WebTx_ERROR_NONE,
    };
}

WebTx_ERROR WebTx_Client::Close() {
    client_->Close(absl::nullopt);
    return WebTx_ERROR_NONE;
}


std::unique_ptr<net::CertVerifier> createPinnedCertVerifier(scoped_refptr<net::X509Certificate> cert, bool insecureSkipVerify) {
    SHA256HashValue fingerprint;
    if (cert) {
        base::StringPiece cert_spki;
        if (net::asn1::ExtractSPKIFromDERCert(
            net::x509_util::CryptoBufferAsStringPiece(
                cert->cert_buffer()),
                &cert_spki)) {
          crypto::SHA256HashString(cert_spki, &fingerprint, sizeof(SHA256HashValue));
        }
    }
    scoped_refptr<net::CertVerifyProc> verify_proc = new CertVerifyProcPinned(fingerprint, insecureSkipVerify); 
    std::unique_ptr<net::CertVerifier> verifier = std::make_unique<net::MultiThreadedCertVerifier>(std::move(verify_proc));
    return verifier;
}

WebTx_ClientPtr _WebTx_ClientCreate(WebTx_ClientOptionsPtr options) {

    std::string ou = base::StrCat({"https://", options->addr, "/"});
    std::string u = base::StrCat({ou, options->path, "/"});

    GURL url = GURL(u);
    url::Origin origin = url::Origin::Create(GURL(ou));

    auto verifier = createPinnedCertVerifier(options->cert, options->insecureSkipVerify);
    net::URLRequestContextBuilder builder;
    builder.DisableHttpCache();
    builder.SetCertVerifier(std::move(verifier));
    auto context = builder.Build();
    auto visitor = std::make_unique<_WebTx_ClientVisitor>(options->visitor);

    net::WebTransportParameters params;
    params.enable_web_transport_http3 = true;

    auto wtc = CreateWebTransportClient(
        url,
        origin,
        visitor.get(),
        net::NetworkIsolationKey(),
        context.get(),
        params
    );

    return new WebTx_Client(std::move(wtc), std::move(context), std::move(visitor));
}

void _CreateWebTxClientOnNetworkThread(WebTx_ClientPtr &client, WebTx_ClientOptionsPtr options, base::WaitableEvent &done) {
    client = _WebTx_ClientCreate(options);
    done.Signal();
}

WebTx_ClientPtr WebTx_Client_Create(WebTx_ClientOptionsPtr options) {
    WebTx_ClientPtr client;
    base::WaitableEvent ready;

    auto runner = WebTx_EnsureInitialized()->GetNetworkTaskRunner();
    runner->PostTask(
        FROM_HERE,
        base::BindOnce(
            &_CreateWebTxClientOnNetworkThread,
            std::ref(client),
            std::ref(options),
            std::ref(ready)
        ));
    ready.Wait();

    return client;
}

WebTx_ERROR _WebTx_Client_Connect(WebTx_ClientPtr self) {
    DCHECK(self);
    return self->Connect();
}

void _WebTx_Client_Connect_OnNetworkThread(WebTx_ClientPtr self, WebTx_ERROR &err, base::WaitableEvent &done) {
    err = _WebTx_Client_Connect(self);
    done.Signal();
}

WebTx_ERROR WebTx_Client_Connect(WebTx_ClientPtr self) {
    base::WaitableEvent ready;
    WebTx_ERROR err;
    auto runner = WebTx_EnsureInitialized()->GetNetworkTaskRunner();
    runner->PostTask(
        FROM_HERE,
        base::BindOnce(
            &_WebTx_Client_Connect_OnNetworkThread,
            self,
            std::ref(err),
            std::ref(ready)
        ));
    ready.Wait();
    return err;
}


WebTx_OpenStreamResult WebTx_Client_OpenOutgoingBidirectionalStream(WebTx_ClientPtr self) {
    DCHECK(self);
    return self->OpenOutgoingBidirectionalStream();
}


WebTx_ERROR _WebTx_Client_Close(WebTx_ClientPtr self) {
    DCHECK(self);
    return self->Close();
}

void _WebTx_Client_Close_OnNetworkThread(WebTx_ClientPtr self, WebTx_ERROR &err, base::WaitableEvent &done) {
    err = _WebTx_Client_Close(self);
    done.Signal();
}

WebTx_ERROR WebTx_Client_Close(WebTx_ClientPtr self) {
    base::WaitableEvent ready;
    WebTx_ERROR err;
    auto runner = WebTx_EnsureInitialized()->GetNetworkTaskRunner();
    runner->PostTask(
        FROM_HERE,
        base::BindOnce(
            &_WebTx_Client_Close_OnNetworkThread,
            self,
            std::ref(err),
            std::ref(ready)
        ));
    ready.Wait();
    return err;
}

void _WebTx_Client_Destroy(WebTx_ClientPtr self) {
    DCHECK(self);
    delete self;
}

WebTx_ERROR WebTx_Client_Destroy(WebTx_ClientPtr self) {
    auto runner = WebTx_EnsureInitialized()->GetNetworkTaskRunner();
    runner->PostTask(
        FROM_HERE,
        base::BindOnce(
            &_WebTx_Client_Destroy,
            self
        ));
    return WebTx_ERROR_NONE;
}


void *WebTx_Create_PinnedCertVerifier(const uint8_t*derBytes, uint64_t len, uint8_t insecureSkipVerify) {
    scoped_refptr<net::X509Certificate> cert;
    if (derBytes && len > 0) {
        cert = net::X509Certificate::CreateFromBytes(base::make_span(derBytes, len));
    }
    bool skip = insecureSkipVerify == 1;
    auto v = createPinnedCertVerifier(cert, skip);
    auto *rawptr = v.get();
    v.release();
    return (void *)rawptr;
}
