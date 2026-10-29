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

int APS5_VABI UndefinedFunction(LibreSsl* ssl) {
    LibreSslPutSslError_nid_no_patch(ssl, ErrorShouldNotHaveBeenCalled);
    return 0;
}

int APS5_VABI UndefinedVoidFunction(void) {
    LibreSslPutSslErrorX_nid_no_patch(ErrorShouldNotHaveBeenCalled);
    return 0;
}

int APS5_VABI AlwaysOk(LibreSsl*) {
    return 1;
}

std::int64_t APS5_VABI TlsDefaultTimeout(void) {
    return DefaultTimeout;
}

int APS5_VABI TlsNew(LibreSsl* ssl) {
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

void APS5_VABI TlsClear(LibreSsl* ssl) {
    void* state = ssl->s3;
    void* internal = Read<void*>(state, Ssl3InternalPointer);
    std::memset(internal, 0, Ssl3InternalSize);
    std::memset(state, 0, Ssl3Size);
    Write<void*>(state, Ssl3InternalPointer, internal);
    Write<unsigned int>(ssl->internal, InternalPacketLength, 0);
    ssl->version = MethodOf(ssl).internal->version;
}

void APS5_VABI TlsFree(LibreSsl* ssl) {
    void* state = ssl->s3;
    if (!state) return;
    free_nid_postfix(Read<void*>(state, Ssl3InternalPointer));
    free_nid_postfix(state);
    ssl->s3 = nullptr;
}

int APS5_VABI DtlsNew(LibreSsl*) {
    NotImplemented_nid_no_patch("SSL_new: DTLS connection state");
}

void APS5_VABI DtlsClear(LibreSsl*) {
    NotImplemented_nid_no_patch("SSL_clear: DTLS connection state");
}

void APS5_VABI DtlsFree(LibreSsl*) {
    NotImplemented_nid_no_patch("SSL_free: DTLS connection state");
}

int APS5_VABI ConnectUnavailable(LibreSsl*) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_connect");
}

int APS5_VABI AcceptUnavailable(LibreSsl*) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_accept");
}

int APS5_VABI ReadUnavailable(LibreSsl*, void*, int) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_read");
}

int APS5_VABI PeekUnavailable(LibreSsl*, void*, int) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_peek");
}

int APS5_VABI WriteUnavailable(LibreSsl*, const void*, int) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_write");
}

int APS5_VABI ShutdownUnavailable(LibreSsl*) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_shutdown");
}

int APS5_VABI PendingUnavailable(const LibreSsl*) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_pending");
}

int APS5_VABI RenegotiateUnavailable(LibreSsl*) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_renegotiate");
}

int APS5_VABI RenegotiateCheckUnavailable(LibreSsl*) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_renegotiate_check");
}

std::int64_t APS5_VABI GetMessageUnavailable(LibreSsl*, int, int, int, std::int64_t, int*) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_get_message");
}

int APS5_VABI ReadBytesUnavailable(LibreSsl*, int, unsigned char*, int, int) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_read_bytes");
}

int APS5_VABI WriteBytesUnavailable(LibreSsl*, int, const void*, int) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_write_bytes");
}

const LibreSslMethod* APS5_VABI GetMethodUnavailable(int) {
    NotImplemented_nid_no_patch("SSL_METHOD get_ssl_method");
}

int APS5_VABI EncUnavailable(LibreSsl*, int) {
    NotImplemented_nid_no_patch("SSL3_ENC_METHOD enc");
}

int APS5_VABI DispatchAlertUnavailable(LibreSsl*) {
    NotImplemented_nid_no_patch("SSL_METHOD ssl_dispatch_alert");
}

int APS5_VABI NumCiphersUnavailable(void) {
    NotImplemented_nid_no_patch("SSL_METHOD num_ciphers");
}

const void* APS5_VABI GetCipherUnavailable(unsigned int) {
    NotImplemented_nid_no_patch("SSL_METHOD get_cipher");
}

const void* APS5_VABI GetCipherByCharUnavailable(const unsigned char*) {
    NotImplemented_nid_no_patch("SSL_METHOD get_cipher_by_char");
}

int APS5_VABI PutCipherByCharUnavailable(const void*, unsigned char*) {
    NotImplemented_nid_no_patch("SSL_METHOD put_cipher_by_char");
}

const LibreSslEncMethod tlsEnc{reinterpret_cast<void*>(EncUnavailable), EncFlagExplicitIv | EncFlagSigalgs | EncFlagSha256Prf | EncFlagTls1_2Ciphers};
const LibreSslEncMethod dtlsEnc{reinterpret_cast<void*>(EncUnavailable), EncFlagExplicitIv};

const LibreSslMethodInternal tlsClientInternal{
    Tls1_2Version, Tls1Version, Tls1_2Version,
    TlsNew, TlsClear, TlsFree,
    UndefinedFunction, ConnectUnavailable,
    ReadUnavailable, PeekUnavailable, WriteUnavailable, ShutdownUnavailable,
    UndefinedFunction, AlwaysOk,
    GetMessageUnavailable, ReadBytesUnavailable, WriteBytesUnavailable,
    PendingUnavailable, GetMethodUnavailable, TlsDefaultTimeout, UndefinedVoidFunction, &tlsEnc};

const LibreSslMethodInternal tlsServerInternal{
    Tls1_2Version, Tls1Version, Tls1_2Version,
    TlsNew, TlsClear, TlsFree,
    AcceptUnavailable, UndefinedFunction,
    ReadUnavailable, PeekUnavailable, WriteUnavailable, ShutdownUnavailable,
    UndefinedFunction, AlwaysOk,
    GetMessageUnavailable, ReadBytesUnavailable, WriteBytesUnavailable,
    PendingUnavailable, GetMethodUnavailable, TlsDefaultTimeout, UndefinedVoidFunction, &tlsEnc};

const LibreSslMethodInternal dtlsClientInternal{
    Dtls1Version, Dtls1Version, Dtls1Version,
    DtlsNew, DtlsClear, DtlsFree,
    UndefinedFunction, ConnectUnavailable,
    ReadUnavailable, PeekUnavailable, WriteUnavailable, ShutdownUnavailable,
    RenegotiateUnavailable, RenegotiateCheckUnavailable,
    GetMessageUnavailable, ReadBytesUnavailable, WriteBytesUnavailable,
    PendingUnavailable, GetMethodUnavailable, TlsDefaultTimeout, UndefinedVoidFunction, &dtlsEnc};

const LibreSslMethodInternal dtlsServerInternal{
    Dtls1Version, Dtls1Version, Dtls1Version,
    DtlsNew, DtlsClear, DtlsFree,
    AcceptUnavailable, UndefinedFunction,
    ReadUnavailable, PeekUnavailable, WriteUnavailable, ShutdownUnavailable,
    RenegotiateUnavailable, RenegotiateCheckUnavailable,
    GetMessageUnavailable, ReadBytesUnavailable, WriteBytesUnavailable,
    PendingUnavailable, GetMethodUnavailable, TlsDefaultTimeout, UndefinedVoidFunction, &dtlsEnc};

const LibreSslMethod tlsClientMethod{
    DispatchAlertUnavailable, NumCiphersUnavailable, GetCipherUnavailable, GetCipherByCharUnavailable, PutCipherByCharUnavailable, &tlsClientInternal};

const LibreSslMethod tlsServerMethod{
    DispatchAlertUnavailable, NumCiphersUnavailable, GetCipherUnavailable, GetCipherByCharUnavailable, PutCipherByCharUnavailable, &tlsServerInternal};

const LibreSslMethod dtlsClientMethod{
    DispatchAlertUnavailable, NumCiphersUnavailable, GetCipherUnavailable, GetCipherByCharUnavailable, PutCipherByCharUnavailable, &dtlsClientInternal};

const LibreSslMethod dtlsServerMethod{
    DispatchAlertUnavailable, NumCiphersUnavailable, GetCipherUnavailable, GetCipherByCharUnavailable, PutCipherByCharUnavailable, &dtlsServerInternal};

}

extern "C" {

bool LibreSslIsUndefinedFunction_nid_no_patch(SslStateFunction function) {
    return function == UndefinedFunction;
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
