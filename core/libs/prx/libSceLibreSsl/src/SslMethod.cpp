#include "prx/libSceLibreSsl/include/Error.hpp"
#include "prx/libSceLibreSsl/include/SslInternal.hpp"
#include "prx/libc/include/Api.hpp"
#include "prx/libc/include/General.hpp"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>

static_assert(sizeof(LibreSslEncMethod) == 16);
static_assert(offsetof(LibreSslEncMethod, encFlags) == 8);
static_assert(sizeof(LibreSslMethodInternal) == 160);
static_assert(offsetof(LibreSslMethodInternal, minVersion) == 4);
static_assert(offsetof(LibreSslMethodInternal, maxVersion) == 6);
static_assert(offsetof(LibreSslMethodInternal, sslNew) == 8);
static_assert(offsetof(LibreSslMethodInternal, sslAccept) == 32);
static_assert(offsetof(LibreSslMethodInternal, sslConnect) == 40);
static_assert(offsetof(LibreSslMethodInternal, sslShutdown) == 72);
static_assert(offsetof(LibreSslMethodInternal, sslRenegotiate) == 80);
static_assert(offsetof(LibreSslMethodInternal, sslPending) == 120);
static_assert(offsetof(LibreSslMethodInternal, getSslMethod) == 128);
static_assert(offsetof(LibreSslMethodInternal, getTimeout) == 136);
static_assert(offsetof(LibreSslMethodInternal, sslVersion) == 144);
static_assert(offsetof(LibreSslMethodInternal, ssl3Enc) == 152);
static_assert(sizeof(LibreSslMethod) == 48);
static_assert(offsetof(LibreSslMethod, internal) == 40);

using namespace SslLayout;

namespace {

constexpr unsigned int EncFlagExplicitIv = 1u << 0;
constexpr unsigned int EncFlagSigalgs = 1u << 1;
constexpr unsigned int EncFlagSha256Prf = 1u << 2;
constexpr unsigned int EncFlagTls1_2Ciphers = 1u << 4;

const LibreSslMethod& MethodOf(const LibreSsl* ssl) {
    const auto* method = static_cast<const LibreSslMethod*>(ssl->method);
    if (!method || !method->internal) throw std::invalid_argument("SSL_METHOD: null method");
    return *method;
}

int APS5_VABI UndefinedFunction_nid_no_patch(LibreSsl* ssl) {
    LibreSslPutSslError_nid_no_patch(ssl, ErrorShouldNotHaveBeenCalled);
    return 0;
}

int APS5_VABI UndefinedVoidFunction_nid_no_patch(void) {
    LibreSslPutSslErrorX_nid_no_patch(ErrorShouldNotHaveBeenCalled);
    return 0;
}

int APS5_VABI AlwaysOk_nid_no_patch(LibreSsl*) {
    return 1;
}

std::int64_t APS5_VABI TlsDefaultTimeout_nid_no_patch(void) {
    return DefaultTimeout;
}

int APS5_VABI TlsNew_nid_no_patch(LibreSsl* ssl) {
    void* state = calloc_nid_postfix(1, Ssl3Size);
    void* internal = calloc_nid_postfix(1, Ssl3InternalSize);
    if (!state || !internal) {
        free_nid_postfix(internal);
        free_nid_postfix(state);
        return 0;
    }
    Write<void*>(state, Ssl3InternalPointer, internal);
    ssl->s3 = state;
    MethodOf(ssl).internal->sslClear(ssl);
    MethodOf(ssl).internal->sslClear(ssl);
    return 1;
}

void APS5_VABI TlsClear_nid_no_patch(LibreSsl* ssl) {
    void* state = ssl->s3;
    void* internal = Read<void*>(state, Ssl3InternalPointer);
    std::memset(internal, 0, Ssl3InternalSize);
    std::memset(state, 0, Ssl3Size);
    Write<void*>(state, Ssl3InternalPointer, internal);
    Write<unsigned int>(ssl->internal, InternalPacketLength, 0);
    ssl->version = MethodOf(ssl).internal->version;
}

void APS5_VABI TlsFree_nid_no_patch(LibreSsl* ssl) {
    void* state = ssl->s3;
    if (!state) return;
    free_nid_postfix(Read<void*>(state, Ssl3InternalPointer));
    free_nid_postfix(state);
    ssl->s3 = nullptr;
}

int APS5_VABI DtlsNew_nid_no_patch(LibreSsl*) {
    NotImplemented_nid_no_patch("SSL_new: DTLS connection state");
}

void APS5_VABI DtlsClear_nid_no_patch(LibreSsl*) {
    NotImplemented_nid_no_patch("SSL_clear: DTLS connection state");
}

void APS5_VABI DtlsFree_nid_no_patch(LibreSsl*) {
    NotImplemented_nid_no_patch("SSL_free: DTLS connection state");
}

int APS5_VABI ConnectUnavailable_nid_no_patch(LibreSsl*) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_connect");
}

int APS5_VABI AcceptUnavailable_nid_no_patch(LibreSsl*) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_accept");
}

int APS5_VABI ReadUnavailable_nid_no_patch(LibreSsl*, void*, int) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_read");
}

int APS5_VABI PeekUnavailable_nid_no_patch(LibreSsl*, void*, int) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_peek");
}

int APS5_VABI WriteUnavailable_nid_no_patch(LibreSsl*, const void*, int) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_write");
}

int APS5_VABI ShutdownUnavailable_nid_no_patch(LibreSsl*) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_shutdown");
}

int APS5_VABI PendingUnavailable_nid_no_patch(const LibreSsl*) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_pending");
}

int APS5_VABI RenegotiateUnavailable_nid_no_patch(LibreSsl*) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_renegotiate");
}

int APS5_VABI RenegotiateCheckUnavailable_nid_no_patch(LibreSsl*) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_renegotiate_check");
}

std::int64_t APS5_VABI GetMessageUnavailable_nid_no_patch(LibreSsl*, int, int, int, std::int64_t, int*) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_get_message");
}

int APS5_VABI ReadBytesUnavailable_nid_no_patch(LibreSsl*, int, unsigned char*, int, int) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_read_bytes");
}

int APS5_VABI WriteBytesUnavailable_nid_no_patch(LibreSsl*, int, const void*, int) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_write_bytes");
}

const LibreSslMethod* APS5_VABI GetMethodUnavailable_nid_no_patch(int) {
    NotImplemented_nid_no_patch("SSL_METHOD get_ssl_method");
}

int APS5_VABI EncUnavailable_nid_no_patch(LibreSsl*, int) {
    NotImplemented_nid_no_patch("SSL3_ENC_METHOD enc");
}

int APS5_VABI DispatchAlertUnavailable_nid_no_patch(LibreSsl*) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_dispatch_alert");
}

int APS5_VABI NumCiphersUnavailable_nid_no_patch(void) {
    NotImplemented_nid_no_patch("SSL_METHOD num_ciphers");
}

const void* APS5_VABI GetCipherUnavailable_nid_no_patch(unsigned int) {
    NotImplemented_nid_no_patch("SSL_METHOD get_cipher");
}

const void* APS5_VABI GetCipherByCharUnavailable_nid_no_patch(const unsigned char*) {
    NotImplemented_nid_no_patch("SSL_METHOD get_cipher_by_char");
}

int APS5_VABI PutCipherByCharUnavailable_nid_no_patch(const void*, unsigned char*) {
    NotImplemented_nid_no_patch("SSL_METHOD put_cipher_by_char");
}

const LibreSslEncMethod tlsEnc{reinterpret_cast<void*>(EncUnavailable_nid_no_patch), EncFlagExplicitIv | EncFlagSigalgs | EncFlagSha256Prf | EncFlagTls1_2Ciphers};
const LibreSslEncMethod dtlsEnc{reinterpret_cast<void*>(EncUnavailable_nid_no_patch), EncFlagExplicitIv};

const LibreSslMethodInternal tlsClientInternal{
    Tls1_2Version, Tls1Version, Tls1_2Version,
    TlsNew_nid_no_patch, TlsClear_nid_no_patch, TlsFree_nid_no_patch,
    UndefinedFunction_nid_no_patch, LibreSslConnect_nid_no_patch,
    LibreSslRead_nid_no_patch, LibreSslPeek_nid_no_patch, LibreSslWrite_nid_no_patch, LibreSslShutdown_nid_no_patch,
    UndefinedFunction_nid_no_patch, AlwaysOk_nid_no_patch,
    GetMessageUnavailable_nid_no_patch, ReadBytesUnavailable_nid_no_patch, WriteBytesUnavailable_nid_no_patch,
    LibreSslPending_nid_no_patch, GetMethodUnavailable_nid_no_patch, TlsDefaultTimeout_nid_no_patch, UndefinedVoidFunction_nid_no_patch, &tlsEnc};

const LibreSslMethodInternal tlsServerInternal{
    Tls1_2Version, Tls1Version, Tls1_2Version,
    TlsNew_nid_no_patch, TlsClear_nid_no_patch, TlsFree_nid_no_patch,
    LibreSslAccept_nid_no_patch, UndefinedFunction_nid_no_patch,
    LibreSslRead_nid_no_patch, LibreSslPeek_nid_no_patch, LibreSslWrite_nid_no_patch, LibreSslShutdown_nid_no_patch,
    UndefinedFunction_nid_no_patch, AlwaysOk_nid_no_patch,
    GetMessageUnavailable_nid_no_patch, ReadBytesUnavailable_nid_no_patch, WriteBytesUnavailable_nid_no_patch,
    LibreSslPending_nid_no_patch, GetMethodUnavailable_nid_no_patch, TlsDefaultTimeout_nid_no_patch, UndefinedVoidFunction_nid_no_patch, &tlsEnc};

const LibreSslMethodInternal dtlsClientInternal{
    Dtls1Version, Dtls1Version, Dtls1Version,
    DtlsNew_nid_no_patch, DtlsClear_nid_no_patch, DtlsFree_nid_no_patch,
    UndefinedFunction_nid_no_patch, ConnectUnavailable_nid_no_patch,
    ReadUnavailable_nid_no_patch, PeekUnavailable_nid_no_patch, WriteUnavailable_nid_no_patch, ShutdownUnavailable_nid_no_patch,
    RenegotiateUnavailable_nid_no_patch, RenegotiateCheckUnavailable_nid_no_patch,
    GetMessageUnavailable_nid_no_patch, ReadBytesUnavailable_nid_no_patch, WriteBytesUnavailable_nid_no_patch,
    PendingUnavailable_nid_no_patch, GetMethodUnavailable_nid_no_patch, TlsDefaultTimeout_nid_no_patch, UndefinedVoidFunction_nid_no_patch, &dtlsEnc};

const LibreSslMethodInternal dtlsServerInternal{
    Dtls1Version, Dtls1Version, Dtls1Version,
    DtlsNew_nid_no_patch, DtlsClear_nid_no_patch, DtlsFree_nid_no_patch,
    AcceptUnavailable_nid_no_patch, UndefinedFunction_nid_no_patch,
    ReadUnavailable_nid_no_patch, PeekUnavailable_nid_no_patch, WriteUnavailable_nid_no_patch, ShutdownUnavailable_nid_no_patch,
    RenegotiateUnavailable_nid_no_patch, RenegotiateCheckUnavailable_nid_no_patch,
    GetMessageUnavailable_nid_no_patch, ReadBytesUnavailable_nid_no_patch, WriteBytesUnavailable_nid_no_patch,
    PendingUnavailable_nid_no_patch, GetMethodUnavailable_nid_no_patch, TlsDefaultTimeout_nid_no_patch, UndefinedVoidFunction_nid_no_patch, &dtlsEnc};

const LibreSslMethod tlsClientMethod{
    DispatchAlertUnavailable_nid_no_patch, NumCiphersUnavailable_nid_no_patch, GetCipherUnavailable_nid_no_patch,
    GetCipherByCharUnavailable_nid_no_patch, PutCipherByCharUnavailable_nid_no_patch, &tlsClientInternal};

const LibreSslMethod tlsServerMethod{
    DispatchAlertUnavailable_nid_no_patch, NumCiphersUnavailable_nid_no_patch, GetCipherUnavailable_nid_no_patch,
    GetCipherByCharUnavailable_nid_no_patch, PutCipherByCharUnavailable_nid_no_patch, &tlsServerInternal};

const LibreSslMethod dtlsClientMethod{
    DispatchAlertUnavailable_nid_no_patch, NumCiphersUnavailable_nid_no_patch, GetCipherUnavailable_nid_no_patch,
    GetCipherByCharUnavailable_nid_no_patch, PutCipherByCharUnavailable_nid_no_patch, &dtlsClientInternal};

const LibreSslMethod dtlsServerMethod{
    DispatchAlertUnavailable_nid_no_patch, NumCiphersUnavailable_nid_no_patch, GetCipherUnavailable_nid_no_patch,
    GetCipherByCharUnavailable_nid_no_patch, PutCipherByCharUnavailable_nid_no_patch, &dtlsServerInternal};

}

extern "C" {

bool LibreSslIsUndefinedFunction_nid_no_patch(SslStateFunction function) {
    return function == UndefinedFunction_nid_no_patch;
}

int LibreSslStateFunction_nid_no_patch(int state) {
    switch (state) {
    case 0: return ErrorFunctionAny;
    case StateBefore: return 73;
    case StateAccept: return 74;
    case StateConnect: return 75;
    case StateOk: return 76;
    case StateConnect | StateAccept | 0x04: return 77;
    case StateBefore | StateConnect: return 78;
    case StateOk | StateConnect: return 79;
    case StateBefore | StateAccept: return 80;
    case StateOk | StateAccept: return 81;
    case StateConnectHelloA: return 2;
    case StateConnectCertB: return 7;
    case StateAcceptHelloA: return 37;
    case StateAcceptHelloC: return 39;
    default: NotImplemented_nid_no_patch("SSLerror: handshake state not modelled");
    }
}

void LibreSslPutSslError_nid_no_patch(const LibreSsl* ssl, int reason) {
    if (!ssl || !ssl->internal) throw std::invalid_argument("SSLerror: null connection state");
    LibreSslPutError_nid_no_patch(ErrorLibrarySsl, LibreSslStateFunction_nid_no_patch(ssl->internal->state), reason);
}

void LibreSslPutSslErrorX_nid_no_patch(int reason) {
    LibreSslPutError_nid_no_patch(ErrorLibrarySsl, ErrorFunctionAny, reason);
}

const LibreSslMethod* APS5_VABI SSLv23_client_method_nid_postfix(void) {
    return TLS_client_method_nid_postfix();
}

const LibreSslMethod* APS5_VABI SSLv23_server_method_nid_postfix(void) {
    return &tlsServerMethod;
}

const LibreSslMethod* APS5_VABI TLS_client_method_nid_postfix(void) {
    return &tlsClientMethod;
}

const LibreSslMethod* APS5_VABI DTLSv1_client_method_nid_postfix(void) {
    return &dtlsClientMethod;
}

const LibreSslMethod* APS5_VABI DTLSv1_server_method_nid_postfix(void) {
    return &dtlsServerMethod;
}

}
