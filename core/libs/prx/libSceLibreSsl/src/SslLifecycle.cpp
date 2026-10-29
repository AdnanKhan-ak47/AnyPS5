#include "prx/libSceLibreSsl/include/SslInternal.hpp"
#include "prx/libc/include/Api.hpp"
#include "prx/libc/include/General.hpp"
#include "prx/libc/include/HostEntropy.hpp"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>

using namespace SslLayout;

namespace {

struct CertificateKey {
    void* certificate;
    void* privateKey;
    const void* digest;
};

struct Certificate {
    CertificateKey* key;
    int valid;
    std::uint64_t maskKeyExchange;
    std::uint64_t maskAuthentication;
    void* dhTemporary;
    void* dhTemporaryCallback;
    int dhTemporaryAuto;
    void* ecdhTemporary;
    void* ecdhTemporaryCallback;
    int ecdhTemporaryAuto;
    CertificateKey keys[7];
    int references;
};

static_assert(sizeof(CertificateKey) == 24);
static_assert(sizeof(Certificate) == 256);
static_assert(offsetof(Certificate, valid) == 8);
static_assert(offsetof(Certificate, keys) == 80);
static_assert(offsetof(Certificate, references) == 248);
static_assert(offsetof(LibreSslCtx, internal) == 112);
static_assert(offsetof(LibreSsl, internal) == 224);
static_assert(offsetof(LibreSslSslInternal, rwstate) == 156);
static_assert(offsetof(LibreSslSslInternal, shutdown) == 168);
static_assert(offsetof(LibreSslSslInternal, state) == 412);
static_assert(offsetof(LibreSslSslInternal, options) == 8);
static_assert(offsetof(LibreSslSslInternal, mode) == 16);
static_assert(offsetof(LibreSslSslInternal, handshakeFunc) == 56);
static_assert(offsetof(LibreSslSslInternal, msgCallback) == 64);
static_assert(offsetof(LibreSslSslInternal, msgCallbackArg) == 72);
static_assert(offsetof(LibreSslSslInternal, verifyCallback) == 88);
static_assert(offsetof(LibreSslSslInternal, readAhead) == 212);
static_assert(offsetof(LibreSslSslInternal, maxCertList) == 296);
static_assert(offsetof(LibreSslSslInternal, rest) == InternalReadState);
static_assert(sizeof(LibreSslSslInternal) == InternalSize);
static_assert(offsetof(LibreSslCtxInternal, generateSessionId) == 120);
static_assert(offsetof(LibreSslCtxInternal, exData) == 248);
static_assert(offsetof(LibreSslCtxInternal, cert) == 264);
static_assert(offsetof(LibreSslCtxInternal, clientCa) == 272);
static_assert(offsetof(LibreSslCtxInternal, maxCertList) == 280);
static_assert(offsetof(LibreSslCtxInternal, alpnClientProtoList) == 416);
static_assert(offsetof(LibreSslCtxInternal, tlsextEcpointformatlist) == 440);

constexpr std::uint64_t VerifyParamDefault = 0x1;
constexpr std::uint64_t VerifyParamOverwrite = 0x2;
constexpr std::uint64_t VerifyParamResetFlags = 0x4;
constexpr std::uint64_t VerifyParamLocked = 0x8;
constexpr std::uint64_t VerifyParamOnce = 0x10;
constexpr std::uint64_t VerifyFlagUseCheckTime = 0x2;

const LibreSslMethod& MethodOf(const LibreSslCtx& ctx) {
    const auto* method = static_cast<const LibreSslMethod*>(ctx.method);
    if (!method || !method->internal) throw std::invalid_argument("SSL_CTX: null method");
    return *method;
}

const LibreSslMethod& MethodOf(const LibreSsl& ssl) {
    const auto* method = static_cast<const LibreSslMethod*>(ssl.method);
    if (!method || !method->internal) throw std::invalid_argument("SSL: null method");
    return *method;
}

LibreSslCtxInternal& InternalOf(LibreSslCtx& ctx, const char* function) {
    if (!ctx.internal) throw std::invalid_argument(std::string(function) + ": null internal state");
    return *ctx.internal;
}

LibreSslSslInternal& InternalOf(LibreSsl& ssl, const char* function) {
    if (!ssl.internal) throw std::invalid_argument(std::string(function) + ": null internal state");
    return *ssl.internal;
}

Certificate* NewCertificate() {
    auto* certificate = static_cast<Certificate*>(calloc_nid_postfix(1, sizeof(Certificate)));
    if (!certificate) return nullptr;
    certificate->key = &certificate->keys[0];
    certificate->references = 1;
    return certificate;
}

Certificate* DuplicateCertificate(const Certificate& source) {
    if (source.dhTemporary || source.ecdhTemporary) NotImplemented_nid_no_patch("SSL_new: duplicating temporary DH or ECDH parameters");
    for (const CertificateKey& key : source.keys)
        if (key.certificate || key.privateKey) NotImplemented_nid_no_patch("SSL_new: duplicating a certificate or private key");
    if (!source.key) throw std::invalid_argument("SSL_new: certificate without an active key");
    auto* copy = static_cast<Certificate*>(calloc_nid_postfix(1, sizeof(Certificate)));
    if (!copy) return nullptr;
    copy->key = &copy->keys[source.key - &source.keys[0]];
    copy->valid = source.valid;
    copy->maskKeyExchange = source.maskKeyExchange;
    copy->maskAuthentication = source.maskAuthentication;
    copy->dhTemporaryCallback = source.dhTemporaryCallback;
    copy->dhTemporaryAuto = source.dhTemporaryAuto;
    copy->ecdhTemporaryCallback = source.ecdhTemporaryCallback;
    copy->ecdhTemporaryAuto = source.ecdhTemporaryAuto;
    copy->references = 1;
    return copy;
}

void FreeCertificate(Certificate* certificate) {
    if (!certificate) return;
    if (std::atomic_ref<int>(certificate->references).fetch_sub(1) - 1 > 0) return;
    if (certificate->dhTemporary || certificate->ecdhTemporary) NotImplemented_nid_no_patch("freeing temporary DH or ECDH parameters");
    for (const CertificateKey& key : certificate->keys)
        if (key.certificate || key.privateKey) NotImplemented_nid_no_patch("freeing a certificate or private key");
    free_nid_postfix(certificate);
}

LibreSslStack* NewEmptyStack() {
    constexpr int initialNodes = 4;
    auto* stack = static_cast<LibreSslStack*>(malloc_nid_postfix(sizeof(LibreSslStack)));
    if (!stack) return nullptr;
    stack->data = static_cast<char**>(calloc_nid_postfix(initialNodes, sizeof(char*)));
    if (!stack->data) {
        free_nid_postfix(stack);
        return nullptr;
    }
    stack->num = 0;
    stack->sorted = 0;
    stack->numAlloc = initialNodes;
    stack->comp = nullptr;
    return stack;
}

void FreeStackShell(LibreSslStack* stack) {
    if (!stack) return;
    free_nid_postfix(stack->data);
    free_nid_postfix(stack);
}

void FreeStackWithElements(LibreSslStack* stack, const char* what) {
    if (!stack) return;
    if (stack->num > 0) {
        if (!stack->data) throw std::invalid_argument(std::string(what) + ": null element array");
        for (int index = 0; index < stack->num; ++index)
            if (stack->data[index]) NotImplemented_nid_no_patch((std::string(what) + ": releasing stored objects").c_str());
    }
    FreeStackShell(stack);
}

bool InheritVerifyParam(LibreSslX509VerifyParam& destination, const LibreSslX509VerifyParam* source) {
    if (!source) return true;
    const std::uint64_t inherited = destination.inheritanceFlags | source->inheritanceFlags;
    if (inherited & VerifyParamOnce) destination.inheritanceFlags = 0;
    if (inherited & VerifyParamLocked) return true;
    const bool toDefault = (inherited & VerifyParamDefault) != 0;
    const bool toOverwrite = (inherited & VerifyParamOverwrite) != 0;
    const auto copies = [&](auto destinationValue, auto sourceValue, auto defaultValue) {
        return toOverwrite || (sourceValue != defaultValue && (toDefault || destinationValue == defaultValue));
    };
    if (copies(destination.purpose, source->purpose, 0)) destination.purpose = source->purpose;
    if (copies(destination.trust, source->trust, 0)) destination.trust = source->trust;
    if (copies(destination.depth, source->depth, -1)) destination.depth = source->depth;
    if (toOverwrite || !(destination.flags & VerifyFlagUseCheckTime)) {
        destination.checkTime = source->checkTime;
        destination.flags &= ~VerifyFlagUseCheckTime;
    }
    if (inherited & VerifyParamResetFlags) destination.flags = 0;
    destination.flags |= source->flags;
    if (copies(destination.policies, source->policies, static_cast<void*>(nullptr)) && source->policies)
        NotImplemented_nid_no_patch("SSL_new: inheriting verification policies");
    const LibreSslX509VerifyParamId* id = source->id;
    if (!id || !destination.id) throw std::invalid_argument("SSL_new: verification parameter without identity checks");
    if (id->hosts || id->peerName || id->email || id->ip)
        NotImplemented_nid_no_patch("SSL_new: inheriting verification host, e-mail or address checks");
    return true;
}

void ClearSsl(LibreSsl& ssl) {
    LibreSslSslInternal& internal = InternalOf(ssl, "SSL_clear");
    if (!ssl.method) {
        LibreSslPutSslError_nid_no_patch(&ssl, ReasonNoMethodSpecified);
        return;
    }
    ssl.error = 0;
    Write<int>(&internal, InternalHit, 0);
    internal.shutdown = 0;
    if (Read<int>(&internal, InternalRenegotiate)) {
        LibreSslPutSslError_nid_no_patch(&ssl, ErrorInternalError);
        return;
    }
    Write<int>(&internal, InternalType, 0);
    internal.state = StateBefore | (ssl.server ? StateAccept : StateConnect);
    ssl.version = MethodOf(ssl).internal->version;
    ssl.clientVersion = ssl.version;
    internal.rwstate = RwNothing;
    Write<int>(&internal, InternalReadState, StateReadHeader);
    if (ssl.encReadCtx || ssl.readHash || internal.encWriteCtx || internal.writeHash || internal.aeadReadCtx || internal.aeadWriteCtx)
        NotImplemented_nid_no_patch("SSL_new: a live cipher or hash context");
    MethodOf(ssl).internal->sslClear(&ssl);
}

void SetBio(LibreSsl& ssl, LibreSslBio* readBio, LibreSslBio* writeBio) {
    auto* buffer = static_cast<LibreSslBio*>(ssl.bbio);
    if (buffer && ssl.wbio == buffer) {
        ssl.wbio = buffer->nextBio;
        buffer->nextBio = nullptr;
    }
    auto* currentRead = static_cast<LibreSslBio*>(ssl.rbio);
    auto* currentWrite = static_cast<LibreSslBio*>(ssl.wbio);
    if (currentRead != readBio && currentRead != currentWrite) LibreSslFreeBioChain_nid_no_patch(currentRead);
    if (currentWrite != writeBio) LibreSslFreeBioChain_nid_no_patch(currentWrite);
    ssl.rbio = readBio;
    ssl.wbio = writeBio;
}

void FreeCopiedLists(LibreSslSslInternal& internal) {
    free_nid_postfix(Read<void*>(&internal, InternalEcPointFormats));
    free_nid_postfix(Read<void*>(&internal, InternalSupportedGroups));
    free_nid_postfix(Read<void*>(&internal, InternalAlpnList));
}

void DestroySsl(LibreSsl& ssl, bool methodReady, bool releaseExData) {
    LibreSslSslInternal& internal = InternalOf(ssl, "SSL_free");
    LibreSslFreeVerifyParam_nid_no_patch(static_cast<LibreSslX509VerifyParam*>(ssl.param), "SSL_free");
    if (releaseExData) LibreSslFreeExData_nid_no_patch(ExClassSsl, &ssl, reinterpret_cast<LibreSslExData*>(reinterpret_cast<unsigned char*>(&internal) + InternalExData));
    if (ssl.bbio) NotImplemented_nid_no_patch("SSL_free: write buffering BIO");
    if (ssl.rbio != ssl.wbio) LibreSslFreeBioChain_nid_no_patch(static_cast<LibreSslBio*>(ssl.rbio));
    LibreSslFreeBioChain_nid_no_patch(static_cast<LibreSslBio*>(ssl.wbio));
    FreeStackShell(static_cast<LibreSslStack*>(ssl.cipherList));
    if (ssl.session) NotImplemented_nid_no_patch("SSL_free: SSL_SESSION");
    if (ssl.encReadCtx || ssl.readHash || internal.encWriteCtx || internal.writeHash || internal.aeadReadCtx || internal.aeadWriteCtx)
        NotImplemented_nid_no_patch("SSL_free: a live cipher or hash context");
    FreeCertificate(static_cast<Certificate*>(ssl.cert));
    free_nid_postfix(ssl.tlsextHostname);
    SSL_CTX_free_nid_postfix(static_cast<LibreSslCtx*>(ssl.initialCtx));
    FreeStackWithElements(Read<LibreSslStack*>(&internal, InternalClientCa), "SSL_free: client CA list");
    if (ssl.method && methodReady) MethodOf(ssl).internal->sslFree(&ssl);
    SSL_CTX_free_nid_postfix(static_cast<LibreSslCtx*>(ssl.ctx));
    FreeCopiedLists(internal);
    free_nid_postfix(ssl.internal);
    free_nid_postfix(&ssl);
}

bool CopyList(LibreSslSslInternal& internal, std::size_t pointerOffset, std::size_t lengthOffset, const void* source, std::uint64_t length, std::size_t elementSize, std::size_t allocationElementSize) {
    void* copy = calloc_nid_postfix(static_cast<std::size_t>(length), allocationElementSize);
    if (!copy) return false;
    std::memcpy(copy, source, static_cast<std::size_t>(length) * elementSize);
    Write<void*>(&internal, pointerOffset, copy);
    Write<std::uint64_t>(&internal, lengthOffset, length);
    return true;
}

bool PopulateSsl(LibreSsl& ssl, LibreSslCtx& ctx, LibreSslCtxInternal& ctxInternal) {
    LibreSslSslInternal& internal = *ssl.internal;
    Write<std::uint16_t>(&internal, InternalMinVersion, ctxInternal.minVersion);
    Write<std::uint16_t>(&internal, InternalMaxVersion, ctxInternal.maxVersion);
    internal.options = ctxInternal.options;
    internal.mode = ctxInternal.mode;
    internal.maxCertList = ctxInternal.maxCertList;
    if (ctxInternal.cert) {
        ssl.cert = DuplicateCertificate(*static_cast<const Certificate*>(ctxInternal.cert));
        if (!ssl.cert) return false;
    } else {
        ssl.cert = nullptr;
    }
    internal.readAhead = ctxInternal.readAhead;
    internal.msgCallback = ctxInternal.msgCallback;
    internal.msgCallbackArg = ctxInternal.msgCallbackArg;
    ssl.verifyMode = ctx.verifyMode;
    ssl.sidCtxLength = ctx.sidCtxLength;
    if (ssl.sidCtxLength > sizeof(ssl.sidCtx)) throw std::invalid_argument("SSL_new: session id context length exceeds its buffer");
    std::memcpy(ssl.sidCtx, ctx.sidCtx, sizeof(ssl.sidCtx));
    internal.verifyCallback = ctxInternal.defaultVerifyCallback;
    Write<void*>(&internal, InternalGenerateSessionId, ctxInternal.generateSessionId);
    ssl.param = LibreSslNewVerifyParam_nid_no_patch();
    if (!ssl.param) return false;
    InheritVerifyParam(*static_cast<LibreSslX509VerifyParam*>(ssl.param), static_cast<const LibreSslX509VerifyParam*>(ctx.param));
    Write<int>(&internal, InternalQuietShutdown, ctxInternal.quietShutdown);
    ssl.maxSendFragment = ctxInternal.maxSendFragment;
    std::atomic_ref<int>(ctx.references).fetch_add(1);
    ssl.ctx = &ctx;
    ssl.tlsextStatusType = -1;
    Write<int>(&internal, InternalOcspResponseLength, -1);
    std::atomic_ref<int>(ctx.references).fetch_add(1);
    ssl.initialCtx = &ctx;
    if (ctxInternal.tlsextEcpointformatlist) {
        if (!CopyList(internal, InternalEcPointFormats, InternalEcPointFormatLength, ctxInternal.tlsextEcpointformatlist, ctxInternal.tlsextEcpointformatlistLength, sizeof(std::uint8_t), sizeof(std::uint8_t))) return false;
    }
    if (ctxInternal.tlsextSupportedgroups) {
        if (!CopyList(internal, InternalSupportedGroups, InternalSupportedGroupsLength, ctxInternal.tlsextSupportedgroups, ctxInternal.tlsextSupportedgroupsLength, sizeof(std::uint16_t), sizeof(std::uint16_t*))) return false;
    }
    if (ctxInternal.alpnClientProtoList) {
        void* list = malloc_nid_postfix(ctxInternal.alpnClientProtoListLen);
        if (!list) return false;
        std::memcpy(list, ctxInternal.alpnClientProtoList, ctxInternal.alpnClientProtoListLen);
        Write<void*>(&internal, InternalAlpnList, list);
        Write<unsigned int>(&internal, InternalAlpnListLength, ctxInternal.alpnClientProtoListLen);
    }
    ssl.verifyResult = 0;
    ssl.method = ctx.method;
    return true;
}

bool PopulateContext(LibreSslCtx& ctx, const LibreSslMethod& method) {
    LibreSslCtxInternal& internal = *ctx.internal;
    ctx.method = &method;
    internal.minVersion = method.internal->minVersion;
    internal.maxVersion = method.internal->maxVersion;
    internal.sessionCacheMode = SessionCacheServer;
    internal.sessionCacheSize = SessionCacheSizeDefault;
    ctx.sessionTimeout = method.internal->getTimeout();
    ctx.references = 1;
    internal.maxCertList = MaxCertListDefault;
    ctx.verifyMode = 0;
    ctx.sidCtxLength = 0;
    internal.cert = NewCertificate();
    if (!internal.cert) return false;
    ctx.certStore = X509_STORE_new_nid_postfix();
    if (!ctx.certStore) return false;
    ctx.param = LibreSslNewVerifyParam_nid_no_patch();
    if (!ctx.param) return false;
    internal.clientCa = NewEmptyStack();
    if (!internal.clientCa) return false;
    if (!LibreSslNewExData_nid_no_patch(ExClassSslCtx, &ctx, reinterpret_cast<LibreSslExData*>(&internal.exData))) return false;
    internal.maxSendFragment = MaxPlainLength;
    HostEntropy_nid_no_patch(internal.tlsextTickKeyName, sizeof(internal.tlsextTickKeyName));
    HostEntropy_nid_no_patch(internal.tlsextTickHmacKey, sizeof(internal.tlsextTickHmacKey));
    HostEntropy_nid_no_patch(internal.tlsextTickAesKey, sizeof(internal.tlsextTickAesKey));
    internal.options |= OptionLegacyServerConnect;
    return true;
}

}

extern "C" {

LibreSslCtx* APS5_VABI SSL_CTX_new_nid_postfix(const LibreSslMethod* method) {
    if (!method) {
        LibreSslPutSslErrorX_nid_no_patch(ReasonNullSslMethodPassed);
        return nullptr;
    }
    if (!method->internal) throw std::invalid_argument(std::string(__func__) + ": null method internal state");
    auto* ctx = static_cast<LibreSslCtx*>(calloc_nid_postfix(1, sizeof(LibreSslCtx)));
    if (!ctx) {
        LibreSslPutSslErrorX_nid_no_patch(ErrorMallocFailure);
        return nullptr;
    }
    ctx->internal = static_cast<LibreSslCtxInternal*>(calloc_nid_postfix(1, sizeof(LibreSslCtxInternal)));
    if (!ctx->internal) {
        free_nid_postfix(ctx);
        LibreSslPutSslErrorX_nid_no_patch(ErrorMallocFailure);
        return nullptr;
    }
    if (SSL_get_ex_data_X509_STORE_CTX_idx_nid_postfix() < 0) {
        LibreSslPutSslErrorX_nid_no_patch(ReasonVerificationSetupProblems);
        LibreSslPutSslErrorX_nid_no_patch(ErrorMallocFailure);
        SSL_CTX_free_nid_postfix(ctx);
        return nullptr;
    }
    if (!PopulateContext(*ctx, *method)) {
        LibreSslPutSslErrorX_nid_no_patch(ErrorMallocFailure);
        SSL_CTX_free_nid_postfix(ctx);
        return nullptr;
    }
    return ctx;
}

void APS5_VABI SSL_CTX_free_nid_postfix(LibreSslCtx* ctx) {
    if (!ctx) return;
    if (std::atomic_ref<int>(ctx->references).fetch_sub(1) - 1 > 0) return;
    LibreSslCtxInternal& internal = InternalOf(*ctx, __func__);
    LibreSslFreeVerifyParam_nid_no_patch(static_cast<LibreSslX509VerifyParam*>(ctx->param), __func__);
    if (internal.sessions) NotImplemented_nid_no_patch("SSL_CTX_free: session cache");
    LibreSslFreeExData_nid_no_patch(ExClassSslCtx, ctx, reinterpret_cast<LibreSslExData*>(&internal.exData));
    X509_STORE_free_nid_postfix(static_cast<LibreSslX509Store*>(ctx->certStore));
    FreeStackShell(static_cast<LibreSslStack*>(ctx->cipherList));
    FreeStackShell(static_cast<LibreSslStack*>(internal.cipherListById));
    FreeCertificate(static_cast<Certificate*>(internal.cert));
    FreeStackWithElements(static_cast<LibreSslStack*>(internal.clientCa), "SSL_CTX_free: client CA list");
    FreeStackWithElements(static_cast<LibreSslStack*>(ctx->extraCerts), "SSL_CTX_free: extra certificates");
    if (internal.srtpProfiles) NotImplemented_nid_no_patch("SSL_CTX_free: SRTP profiles");
    if (internal.clientCertEngine) NotImplemented_nid_no_patch("SSL_CTX_free: client certificate engine");
    free_nid_postfix(internal.tlsextEcpointformatlist);
    free_nid_postfix(internal.tlsextSupportedgroups);
    free_nid_postfix(internal.alpnClientProtoList);
    free_nid_postfix(ctx->internal);
    free_nid_postfix(ctx);
}

LibreSsl* APS5_VABI SSL_new_nid_postfix(LibreSslCtx* ctx) {
    if (!ctx) {
        LibreSslPutSslErrorX_nid_no_patch(ReasonNullSslCtx);
        return nullptr;
    }
    if (!ctx->method) {
        LibreSslPutSslErrorX_nid_no_patch(ReasonSslCtxHasNoDefaultSslVersion);
        return nullptr;
    }
    LibreSslCtxInternal& ctxInternal = InternalOf(*ctx, __func__);
    const LibreSslMethod& method = MethodOf(*ctx);
    auto* ssl = static_cast<LibreSsl*>(calloc_nid_postfix(1, sizeof(LibreSsl)));
    if (!ssl) {
        LibreSslPutSslErrorX_nid_no_patch(ErrorMallocFailure);
        return nullptr;
    }
    ssl->internal = static_cast<LibreSslSslInternal*>(calloc_nid_postfix(1, sizeof(LibreSslSslInternal)));
    if (!ssl->internal) {
        free_nid_postfix(ssl);
        LibreSslPutSslErrorX_nid_no_patch(ErrorMallocFailure);
        return nullptr;
    }
    bool created = false;
    try {
        created = PopulateSsl(*ssl, *ctx, ctxInternal) && method.internal->sslNew(ssl) != 0;
    } catch (...) {
        DestroySsl(*ssl, false, false);
        throw;
    }
    if (!created) {
        DestroySsl(*ssl, false, true);
        LibreSslPutSslErrorX_nid_no_patch(ErrorMallocFailure);
        return nullptr;
    }
    ssl->references = 1;
    ssl->server = LibreSslIsUndefinedFunction_nid_no_patch(method.internal->sslAccept) ? 0 : 1;
    ClearSsl(*ssl);
    LibreSslNewExData_nid_no_patch(ExClassSsl, ssl, reinterpret_cast<LibreSslExData*>(reinterpret_cast<unsigned char*>(ssl->internal) + InternalExData));
    return ssl;
}

void APS5_VABI SSL_free_nid_postfix(LibreSsl* ssl) {
    if (!ssl) return;
    if (std::atomic_ref<int>(ssl->references).fetch_sub(1) - 1 > 0) return;
    DestroySsl(*ssl, true, true);
}

int APS5_VABI SSL_set_fd_nid_postfix(LibreSsl* ssl, int fd) {
    if (!ssl) throw std::invalid_argument(std::string(__func__) + ": null connection");
    LibreSslBio* bio = LibreSslNewSocketBio_nid_no_patch(fd);
    if (!bio) {
        LibreSslPutSslError_nid_no_patch(ssl, ErrorBufferLibrary);
        return 0;
    }
    SetBio(*ssl, bio, bio);
    return 1;
}

int APS5_VABI SSL_get_fd_nid_postfix(const LibreSsl* ssl) {
    if (!ssl) throw std::invalid_argument(std::string(__func__) + ": null connection");
    return LibreSslBioDescriptor_nid_no_patch(static_cast<const LibreSslBio*>(ssl->rbio));
}

}
