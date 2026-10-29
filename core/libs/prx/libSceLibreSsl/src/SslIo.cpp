#include "prx/libSceLibreSsl/include/Api.hpp"
#include "prx/libSceLibreSsl/include/SslInternal.hpp"
#include "prx/libSceLibreSsl/include/TlsEngine.hpp"
#include "prx/libc/include/Api.hpp"
#include "prx/libc/include/General.hpp"
#include "prx/libkernel/Socket/include/SocketError.hpp"
#include <mbedtls/x509.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>

using namespace SslLayout;
using EngineResult = LibreSslTls::Result;
using Tls = LibreSslTls::Connection;

namespace {

struct Session {
    std::unique_ptr<Tls> tls;
    bool failed = false;
    std::uint64_t receivedSeen = 0;
    std::uint64_t sentSeen = 0;
};

std::mutex registryMutex;
std::unordered_map<const LibreSsl*, Session> registry;

Session* Find(const LibreSsl* ssl) {
    std::lock_guard<std::mutex> lock(registryMutex);
    const auto found = registry.find(ssl);
    return found == registry.end() ? nullptr : &found->second;
}

Session& Create(const LibreSsl* ssl, std::unique_ptr<Tls> tls) {
    std::lock_guard<std::mutex> lock(registryMutex);
    const auto [position, inserted] = registry.emplace(ssl, Session{std::move(tls)});
    if (!inserted) throw std::logic_error("SSL: a TLS connection already exists for this SSL");
    return position->second;
}

[[noreturn]] void Unmodelled(const char* function, const std::string& what) {
    NotImplemented_nid_no_patch((std::string(function) + ": " + what).c_str());
}

LibreSsl& SslOf(LibreSsl* ssl, const char* function) {
    if (!ssl) throw std::invalid_argument(std::string(function) + ": null connection");
    return *ssl;
}

LibreSslSslInternal& InternalOf(LibreSsl& ssl, const char* function) {
    if (!ssl.internal) throw std::invalid_argument(std::string(function) + ": null internal state");
    return *ssl.internal;
}

const LibreSslMethodInternal& MethodOf(const LibreSsl& ssl, const char* function) {
    const auto* method = static_cast<const LibreSslMethod*>(ssl.method);
    if (!method || !method->internal) throw std::invalid_argument(std::string(function) + ": null method");
    return *method->internal;
}

void* Ssl3InternalOf(const LibreSsl& ssl, const char* function) {
    if (!ssl.s3) throw std::invalid_argument(std::string(function) + ": null SSL3 state");
    void* internal = Read<void*>(ssl.s3, Ssl3InternalPointer);
    if (!internal) throw std::invalid_argument(std::string(function) + ": null SSL3 internal state");
    return internal;
}

void SetGuestErrno(int value) {
    *__error_nid_postfix() = value;
}

void SetHostErrno(int hostError) {
    SetGuestErrno(GuestSockets::GuestErrorFromHost(hostError));
}

LibreSslBio& SharedBio(LibreSsl& ssl, const char* function) {
    auto* read = static_cast<LibreSslBio*>(ssl.rbio);
    auto* write = static_cast<LibreSslBio*>(ssl.wbio);
    if (!read || !write) Unmodelled(function, "the connection has no BIO");
    if (read != write) Unmodelled(function, "separate read and write BIOs");
    return *read;
}

void SetRetry(LibreSslBio& bio, int direction) {
    bio.flags &= ~(BioFlagRead | BioFlagWrite | BioFlagIoSpecial | BioFlagShouldRetry);
    if (direction) bio.flags |= direction | BioFlagShouldRetry;
}

void Account(LibreSslBio& bio, Session& session) {
    const std::uint64_t received = session.tls->BytesReceived();
    const std::uint64_t sent = session.tls->BytesSent();
    bio.numRead += received - session.receivedSeen;
    bio.numWrite += sent - session.sentSeen;
    session.receivedSeen = received;
    session.sentSeen = sent;
}

bool Wait(LibreSslSslInternal& internal, LibreSslBio& bio, EngineResult result, const Tls& tls) {
    if (result != EngineResult::WantRead && result != EngineResult::WantWrite) return false;
    if (tls.SystemError()) SetHostErrno(tls.SystemError());
    internal.rwstate = result == EngineResult::WantRead ? RwReading : RwWriting;
    SetRetry(bio, result == EngineResult::WantRead ? BioFlagRead : BioFlagWrite);
    return true;
}

void Succeeded(LibreSslSslInternal& internal, LibreSslBio& bio) {
    internal.rwstate = RwNothing;
    SetRetry(bio, 0);
}

int SystemFailure(LibreSslSslInternal& internal, LibreSslBio& bio, const Tls& tls) {
    SetRetry(bio, 0);
    switch (tls.LastDirection()) {
    case LibreSslTls::Direction::Read: internal.rwstate = RwReading; break;
    case LibreSslTls::Direction::Write: internal.rwstate = RwWriting; break;
    case LibreSslTls::Direction::None: internal.rwstate = RwNothing; break;
    }
    if (!tls.SystemError()) return 0;
    SetHostErrno(tls.SystemError());
    return -1;
}

void ReceivedCloseNotify(LibreSsl& ssl, LibreSslSslInternal& internal, const char* function) {
    internal.shutdown |= ShutdownReceived;
    Write<int>(Ssl3InternalOf(ssl, function), Ssl3InternalWarnAlert, AlertCloseNotify);
}

bool ClampVersionRange(std::uint16_t& low, std::uint16_t& high, std::uint16_t clampLow, std::uint16_t clampHigh) {
    if (clampLow > clampHigh || low > high) return false;
    if (clampHigh < low || clampLow > high) return false;
    low = std::max(low, clampLow);
    high = std::min(high, clampHigh);
    return true;
}

void RequireTls12(const LibreSsl& ssl, const LibreSslSslInternal& internal, const char* function) {
    const std::uint64_t options = internal.options;
    std::uint16_t low = 0;
    std::uint16_t high = Tls1_2Version;
    if (!(options & OptionNoTlsV1)) low = Tls1Version;
    else if (!(options & OptionNoTlsV1_1)) low = Tls1_1Version;
    else if (!(options & OptionNoTlsV1_2)) low = Tls1_2Version;
    if ((options & OptionNoTlsV1_2) && low < Tls1_2Version) high = Tls1_1Version;
    if ((options & OptionNoTlsV1_1) && low < Tls1_1Version) high = Tls1Version;
    if ((options & OptionNoTlsV1) && low < Tls1Version) high = 0;
    const LibreSslMethodInternal& method = MethodOf(ssl, function);
    if (low == 0 || high == 0 || !ClampVersionRange(low, high, Read<std::uint16_t>(&internal, InternalMinVersion), Read<std::uint16_t>(&internal, InternalMaxVersion)) ||
        !ClampVersionRange(low, high, method.minVersion, method.maxVersion))
        Unmodelled(function, "no protocol version is enabled");
    if (high < Tls1_2Version) Unmodelled(function, "TLS 1.2 is disabled and the engine speaks only TLS 1.2");
}

bool Populated(const void* stack) {
    return stack && static_cast<const LibreSslStack*>(stack)->num > 0;
}

void RequireModelled(const LibreSsl& ssl, const LibreSslSslInternal& internal, bool server, const char* function) {
    if (!ssl.ctx || !static_cast<const LibreSslCtx*>(ssl.ctx)->internal) throw std::invalid_argument(std::string(function) + ": null context");
    const LibreSslCtx& ctx = *static_cast<const LibreSslCtx*>(ssl.ctx);
    if (internal.msgCallback) Unmodelled(function, "a message callback is set");
    if (ctx.internal->infoCallback) Unmodelled(function, "an info callback is set");
    if (ssl.session) Unmodelled(function, "an SSL_SESSION is set");
    if (server) {
        if (ssl.verifyMode & LibreSslTls::SslVerifyPeer) Unmodelled(function, "client certificate verification is requested");
        return;
    }
    if (internal.verifyCallback) Unmodelled(function, "a verify callback is set");
    if (ctx.internal->appVerifyCallback) Unmodelled(function, "a certificate verify callback is set");
    if (Read<void*>(&internal, InternalAlpnList)) Unmodelled(function, "an ALPN protocol list is set");
    if (ssl.tlsextStatusType != -1) Unmodelled(function, "a certificate status request is set");
    const auto* param = static_cast<const LibreSslX509VerifyParam*>(ssl.param);
    if (!param) throw std::invalid_argument(std::string(function) + ": null verification parameters");
    if (param->depth != -1) Unmodelled(function, "a verification depth limit is set");
    const auto* store = static_cast<const LibreSslX509Store*>(ctx.certStore);
    if (!store) throw std::invalid_argument(std::string(function) + ": null certificate store");
    if (Populated(store->objects) || Populated(store->lookupMethods)) Unmodelled(function, "the certificate store holds trusted certificates or lookups");
}

std::unique_ptr<Tls> MakeConnection(LibreSsl& ssl, bool server, const char* function) {
    const LibreSslSslInternal& internal = InternalOf(ssl, function);
    RequireTls12(ssl, internal, function);
    RequireModelled(ssl, internal, server, function);
    LibreSslBio& bio = SharedBio(ssl, function);
    const int descriptor = LibreSslBioDescriptor_nid_no_patch(&bio);
    auto tls = std::make_unique<Tls>(server);
    try {
        tls->SetSocket(descriptor);
    } catch (const std::invalid_argument&) {
        Unmodelled(function, "descriptor " + std::to_string(descriptor) + " is not a guest socket");
    }
    tls->SetVerifyMode(!server && ssl.verifyMode != 0 ? LibreSslTls::SslVerifyPeer : LibreSslTls::SslVerifyNone);
    if (!server && ssl.tlsextHostname) tls->SetServerName(ssl.tlsextHostname);
    return tls;
}

std::int64_t VerifyResult(const Tls& tls, const char* function) {
    if (!(tls.VerifyFlags() & MBEDTLS_X509_BADCERT_NOT_TRUSTED)) Unmodelled(function, "the engine verified a chain against an empty trust store");
    switch (tls.PeerChain()) {
    case LibreSslTls::ChainShape::SelfSignedLeaf: return VerifyErrorDepthZeroSelfSigned;
    case LibreSslTls::ChainShape::EndsInSelfSigned: return VerifyErrorSelfSignedInChain;
    case LibreSslTls::ChainShape::Incomplete: return VerifyErrorUnableToGetIssuerLocally;
    case LibreSslTls::ChainShape::None: break;
    }
    Unmodelled(function, "the engine saw no peer certificate chain");
}

int HandshakeFailure(LibreSsl& ssl, LibreSslSslInternal& internal, LibreSslBio& bio, Session& session, bool server, const char* function) {
    const Tls& tls = *session.tls;
    switch (tls.FailureKind()) {
    case LibreSslTls::Failure::VerifyFailed:
        if (server) break;
        ssl.verifyResult = VerifyResult(tls, function);
        internal.state = StateConnectCertB;
        Succeeded(internal, bio);
        LibreSslPutSslError_nid_no_patch(&ssl, ReasonCertificateVerifyFailed);
        session.failed = true;
        return -1;
    case LibreSslTls::Failure::NoSharedCipher:
        internal.state = StateAcceptHelloC;
        Succeeded(internal, bio);
        LibreSslPutSslError_nid_no_patch(&ssl, ReasonNoSharedCipher);
        session.failed = true;
        return -1;
    case LibreSslTls::Failure::BadWriteRetry:
    case LibreSslTls::Failure::Other:
    case LibreSslTls::Failure::None: break;
    }
    Unmodelled(function, "the engine failed the handshake: " + tls.FailureText());
}

int Handshake(LibreSsl& ssl, bool server, const char* function) {
    LibreSslSslInternal& internal = InternalOf(ssl, function);
    ERR_clear_error_nid_postfix();
    SetGuestErrno(0);
    if (!(internal.state & StateInit) || (internal.state & StateBefore)) LibreSslClear_nid_no_patch(&ssl);
    ssl.server = server ? 1 : 0;
    Session* session = Find(&ssl);
    if (!session) {
        if (!(internal.state & StateBefore)) throw std::logic_error(std::string(function) + ": a started handshake has no TLS connection");
        session = &Create(&ssl, MakeConnection(ssl, server, function));
        internal.state = server ? StateAcceptHelloA : StateConnectHelloA;
    } else if (session->failed) {
        Unmodelled(function, "continuing a handshake that already failed");
    }
    LibreSslBio& bio = SharedBio(ssl, function);
    const EngineResult result = session->tls->Handshake();
    Account(bio, *session);
    if (Wait(internal, bio, result, *session->tls)) return -1;
    switch (result) {
    case EngineResult::Done:
        if (!server) ssl.verifyResult = VerifyResult(*session->tls, function);
        internal.state = StateOk;
        Succeeded(internal, bio);
        return 1;
    case EngineResult::ZeroReturn:
        ReceivedCloseNotify(ssl, internal, function);
        internal.rwstate = RwReading;
        SetRetry(bio, 0);
        return 0;
    case EngineResult::Syscall: return SystemFailure(internal, bio, *session->tls);
    case EngineResult::Ssl: return HandshakeFailure(ssl, internal, bio, *session, server, function);
    case EngineResult::WantRead:
    case EngineResult::WantWrite: break;
    }
    throw std::logic_error(std::string(function) + ": unhandled engine result");
}

int RunHandshakeFunction(LibreSsl& ssl, LibreSslSslInternal& internal) {
    if (!internal.handshakeFunc) throw std::invalid_argument("SSL: no handshake function");
    const int result = reinterpret_cast<SslStateFunction>(internal.handshakeFunc)(&ssl);
    if (result == 0) {
        LibreSslPutSslError_nid_no_patch(&ssl, ReasonSslHandshakeFailure);
        return -1;
    }
    return result;
}

Session& Established(LibreSsl& ssl, const char* function) {
    Session* session = Find(&ssl);
    if (!session) throw std::logic_error(std::string(function) + ": a finished handshake has no TLS connection");
    if (session->failed) Unmodelled(function, "I/O after a failed handshake");
    return *session;
}

int ReadApplicationData(LibreSsl& ssl, void* buffer, int length, bool peek, const char* function) {
    LibreSslSslInternal& internal = InternalOf(ssl, function);
    SetGuestErrno(0);
    if (length < 0) {
        LibreSslPutSslError_nid_no_patch(&ssl, ErrorInternalError);
        return -1;
    }
    if (internal.state & StateInit) {
        const int result = RunHandshakeFunction(ssl, internal);
        if (result < 0) return result;
    }
    Session& session = Established(ssl, function);
    LibreSslBio& bio = SharedBio(ssl, function);
    std::size_t transferred = 0;
    const EngineResult result = session.tls->Read(buffer, static_cast<std::size_t>(length), transferred, peek);
    Account(bio, session);
    if (Wait(internal, bio, result, *session.tls)) return -1;
    switch (result) {
    case EngineResult::Done:
        Succeeded(internal, bio);
        return static_cast<int>(transferred);
    case EngineResult::ZeroReturn:
        ReceivedCloseNotify(ssl, internal, function);
        Succeeded(internal, bio);
        return 0;
    case EngineResult::Syscall: return SystemFailure(internal, bio, *session.tls);
    case EngineResult::Ssl: Unmodelled(function, "the engine failed the read: " + session.tls->FailureText());
    case EngineResult::WantRead:
    case EngineResult::WantWrite: break;
    }
    throw std::logic_error(std::string(function) + ": unhandled engine result");
}

void SetAcceptState(LibreSsl& ssl, LibreSslSslInternal& internal, const char* function) {
    const LibreSslMethodInternal& method = MethodOf(ssl, function);
    if (ssl.encReadCtx || ssl.readHash || internal.encWriteCtx || internal.aeadReadCtx || internal.aeadWriteCtx || internal.writeHash)
        Unmodelled(function, "freeing a live cipher or hash context");
    ssl.server = 1;
    internal.shutdown = 0;
    internal.state = StateAccept | StateBefore;
    internal.handshakeFunc = reinterpret_cast<void*>(method.sslAccept);
}

}

extern "C" {

void LibreSslReleaseConnection_nid_no_patch(const LibreSsl* ssl) {
    std::lock_guard<std::mutex> lock(registryMutex);
    registry.erase(ssl);
}

std::size_t LibreSslConnectionCount_nid_no_patch() {
    std::lock_guard<std::mutex> lock(registryMutex);
    return registry.size();
}

int APS5_VABI LibreSslConnect_nid_no_patch(LibreSsl* ssl) {
    return Handshake(SslOf(ssl, "SSL_connect"), false, "SSL_connect");
}

int APS5_VABI LibreSslAccept_nid_no_patch(LibreSsl* ssl) {
    return Handshake(SslOf(ssl, "SSL_accept"), true, "SSL_accept");
}

int APS5_VABI LibreSslRead_nid_no_patch(LibreSsl* ssl, void* buffer, int length) {
    return ReadApplicationData(SslOf(ssl, "SSL_read"), buffer, length, false, "SSL_read");
}

int APS5_VABI LibreSslPeek_nid_no_patch(LibreSsl* ssl, void* buffer, int length) {
    return ReadApplicationData(SslOf(ssl, "SSL_peek"), buffer, length, true, "SSL_peek");
}

int APS5_VABI LibreSslWrite_nid_no_patch(LibreSsl* ssl, const void* buffer, int length) {
    const char* function = "SSL_write";
    LibreSsl& connection = SslOf(ssl, function);
    LibreSslSslInternal& internal = InternalOf(connection, function);
    SetGuestErrno(0);
    if (length < 0) {
        LibreSslPutSslError_nid_no_patch(&connection, ErrorInternalError);
        return -1;
    }
    internal.rwstate = RwNothing;
    if (internal.state & StateInit) {
        const int result = RunHandshakeFunction(connection, internal);
        if (result < 0) return result;
    }
    Session& session = Established(connection, function);
    LibreSslBio& bio = SharedBio(connection, function);
    LibreSslTls::WriteOptions options;
    options.fragment = connection.maxSendFragment;
    options.partial = (internal.mode & ModeEnablePartialWrite) != 0;
    options.movingBuffer = (internal.mode & ModeAcceptMovingWriteBuffer) != 0;
    std::size_t transferred = 0;
    const EngineResult result = session.tls->Write(buffer, static_cast<std::size_t>(length), transferred, options);
    Account(bio, session);
    if (Wait(internal, bio, result, *session.tls)) return -1;
    switch (result) {
    case EngineResult::Done:
        Succeeded(internal, bio);
        return static_cast<int>(transferred);
    case EngineResult::Syscall:
        if (length == 0) {
            Succeeded(internal, bio);
            return 0;
        }
        SystemFailure(internal, bio, *session.tls);
        return -1;
    case EngineResult::Ssl:
        if (session.tls->FailureKind() != LibreSslTls::Failure::BadWriteRetry) Unmodelled(function, "the engine failed the write: " + session.tls->FailureText());
        LibreSslPutSslError_nid_no_patch(&connection, ReasonBadWriteRetry);
        return -1;
    case EngineResult::ZeroReturn:
    case EngineResult::WantRead:
    case EngineResult::WantWrite: break;
    }
    throw std::logic_error(std::string(function) + ": unhandled engine result");
}

int APS5_VABI LibreSslShutdown_nid_no_patch(LibreSsl* ssl) {
    const char* function = "SSL_shutdown";
    LibreSsl& connection = SslOf(ssl, function);
    LibreSslSslInternal& internal = InternalOf(connection, function);
    if (Read<int>(&internal, InternalQuietShutdown) || internal.state == StateBefore) {
        internal.shutdown = ShutdownSent | ShutdownReceived;
        return 1;
    }
    Session& session = Established(connection, function);
    LibreSslBio& bio = SharedBio(connection, function);
    bool complete = false;
    const EngineResult result = session.tls->Shutdown(complete);
    Account(bio, session);
    if (session.tls->SentShutdown()) internal.shutdown |= ShutdownSent;
    if (session.tls->ReceivedShutdown()) internal.shutdown |= ShutdownReceived;
    if (Wait(internal, bio, result, *session.tls)) return -1;
    switch (result) {
    case EngineResult::Done:
        if (session.tls->FatalAlertReceived()) Unmodelled(function, "the peer sent a fatal alert");
        Succeeded(internal, bio);
        return complete ? 1 : 0;
    case EngineResult::Syscall:
        SystemFailure(internal, bio, *session.tls);
        return -1;
    case EngineResult::Ssl: Unmodelled(function, "the engine failed the shutdown: " + session.tls->FailureText());
    case EngineResult::ZeroReturn:
    case EngineResult::WantRead:
    case EngineResult::WantWrite: break;
    }
    throw std::logic_error(std::string(function) + ": unhandled engine result");
}

int APS5_VABI LibreSslPending_nid_no_patch(const LibreSsl* ssl) {
    const Session* session = Find(ssl);
    if (!session) return 0;
    return static_cast<int>(std::min<std::size_t>(session->tls->Pending(), 0x7fffffff));
}

int APS5_VABI SSL_connect_nid_postfix(LibreSsl* ssl) {
    LibreSsl& connection = SslOf(ssl, __func__);
    if (!InternalOf(connection, __func__).handshakeFunc) SSL_set_connect_state_nid_postfix(&connection);
    return MethodOf(connection, __func__).sslConnect(&connection);
}

int APS5_VABI SSL_accept_nid_postfix(LibreSsl* ssl) {
    LibreSsl& connection = SslOf(ssl, __func__);
    LibreSslSslInternal& internal = InternalOf(connection, __func__);
    if (!internal.handshakeFunc) SetAcceptState(connection, internal, __func__);
    return MethodOf(connection, __func__).sslAccept(&connection);
}

int APS5_VABI SSL_read_nid_postfix(LibreSsl* ssl, void* buffer, int length) {
    LibreSsl& connection = SslOf(ssl, __func__);
    LibreSslSslInternal& internal = InternalOf(connection, __func__);
    if (!internal.handshakeFunc) {
        LibreSslPutSslError_nid_no_patch(&connection, ReasonUninitialized);
        return -1;
    }
    if (internal.shutdown & ShutdownReceived) {
        internal.rwstate = RwNothing;
        return 0;
    }
    return MethodOf(connection, __func__).sslRead(&connection, buffer, length);
}

int APS5_VABI SSL_peek_nid_postfix(LibreSsl* ssl, void* buffer, int length) {
    LibreSsl& connection = SslOf(ssl, __func__);
    LibreSslSslInternal& internal = InternalOf(connection, __func__);
    if (!internal.handshakeFunc) {
        LibreSslPutSslError_nid_no_patch(&connection, ReasonUninitialized);
        return -1;
    }
    if (internal.shutdown & ShutdownReceived) return 0;
    return MethodOf(connection, __func__).sslPeek(&connection, buffer, length);
}

int APS5_VABI SSL_write_nid_postfix(LibreSsl* ssl, const void* buffer, int length) {
    LibreSsl& connection = SslOf(ssl, __func__);
    LibreSslSslInternal& internal = InternalOf(connection, __func__);
    if (!internal.handshakeFunc) {
        LibreSslPutSslError_nid_no_patch(&connection, ReasonUninitialized);
        return -1;
    }
    if (internal.shutdown & ShutdownSent) {
        internal.rwstate = RwNothing;
        LibreSslPutSslError_nid_no_patch(&connection, ReasonProtocolIsShutdown);
        return -1;
    }
    return MethodOf(connection, __func__).sslWrite(&connection, buffer, length);
}

int APS5_VABI SSL_shutdown_nid_postfix(LibreSsl* ssl) {
    LibreSsl& connection = SslOf(ssl, __func__);
    LibreSslSslInternal& internal = InternalOf(connection, __func__);
    if (!internal.handshakeFunc) {
        LibreSslPutSslError_nid_no_patch(&connection, ReasonUninitialized);
        return -1;
    }
    if (internal.state & StateInit) return 1;
    return MethodOf(connection, __func__).sslShutdown(&connection);
}

int APS5_VABI SSL_pending_nid_postfix(const LibreSsl* ssl) {
    if (!ssl) throw std::invalid_argument(std::string(__func__) + ": null connection");
    return MethodOf(*ssl, __func__).sslPending(ssl);
}

int APS5_VABI SSL_get_error_nid_postfix(const LibreSsl* ssl, int result) {
    if (result > 0) return SslErrorNone;
    const std::uint64_t queued = ERR_peek_error_nid_postfix();
    if (queued) return ((queued >> 24) & 0xff) == static_cast<std::uint64_t>(ErrorLibrarySys) ? SslErrorSyscall : SslErrorSsl;
    if (!ssl) throw std::invalid_argument(std::string(__func__) + ": null connection");
    if (!ssl->internal) throw std::invalid_argument(std::string(__func__) + ": null internal state");
    const LibreSslSslInternal& internal = *ssl->internal;
    const auto special = [](const LibreSslBio& bio) {
        if (bio.retryReason == BioRetryConnect) return SslErrorWantConnect;
        if (bio.retryReason == BioRetryAccept) return SslErrorWantAccept;
        return SslErrorSyscall;
    };
    const auto classify = [&](const void* pointer, int preferred, int other) {
        if (!pointer) throw std::invalid_argument("SSL_get_error: null BIO");
        const auto& bio = *static_cast<const LibreSslBio*>(pointer);
        if (bio.flags & preferred) return preferred == BioFlagRead ? SslErrorWantRead : SslErrorWantWrite;
        if (bio.flags & other) return other == BioFlagRead ? SslErrorWantRead : SslErrorWantWrite;
        if (bio.flags & BioFlagIoSpecial) return special(bio);
        return 0;
    };
    if (result < 0 && internal.rwstate == RwReading) {
        if (const int error = classify(ssl->rbio, BioFlagRead, BioFlagWrite)) return error;
    }
    if (result < 0 && internal.rwstate == RwWriting) {
        if (const int error = classify(ssl->wbio, BioFlagWrite, BioFlagRead)) return error;
    }
    if (result < 0 && internal.rwstate == RwX509Lookup) return SslErrorWantX509Lookup;
    if (result == 0 && (internal.shutdown & ShutdownReceived) && Read<int>(Ssl3InternalOf(*ssl, __func__), Ssl3InternalWarnAlert) == AlertCloseNotify)
        return SslErrorZeroReturn;
    return SslErrorSyscall;
}

}
