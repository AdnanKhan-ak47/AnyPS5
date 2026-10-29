#ifndef CORE_LIBS_PRX_LIBSCELIBRESSL_INCLUDE_TLSENGINE_HPP
#define CORE_LIBS_PRX_LIBSCELIBRESSL_INCLUDE_TLSENGINE_HPP

#include <cstddef>
#include <cstdint>
#include <memory>

namespace LibreSslTls {

enum class Result { Done, WantRead, WantWrite, ZeroReturn, Syscall, Ssl };

inline constexpr int SslErrorNone = 0;
inline constexpr int SslErrorSsl = 1;
inline constexpr int SslErrorWantRead = 2;
inline constexpr int SslErrorWantWrite = 3;
inline constexpr int SslErrorSyscall = 5;
inline constexpr int SslErrorZeroReturn = 6;

inline constexpr int SslVerifyNone = 0x00;
inline constexpr int SslVerifyPeer = 0x01;
inline constexpr int SslVerifyFailIfNoPeerCert = 0x02;
inline constexpr int SslVerifyClientOnce = 0x04;

int ToSslError(Result result);

class Connection {
public:
    explicit Connection(bool server);
    ~Connection();
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;
    Connection(Connection&&) = delete;
    Connection& operator=(Connection&&) = delete;

    void SetSocket(int guestFd);
    int Socket() const;
    void SetHostname(const char* name);
    void SetVerifyMode(int sslVerifyMode);
    void TrustCertificates(const unsigned char* pem, std::size_t size);
    void UseCertificate(const unsigned char* certificatePem, std::size_t certificateSize, const unsigned char* keyPem, std::size_t keySize);

    Result Handshake();
    Result Read(void* buffer, std::size_t size, std::size_t& transferred, bool peek);
    Result Write(const void* buffer, std::size_t size, std::size_t& transferred);
    Result Shutdown(bool& complete);
    std::size_t Pending() const;

    bool HandshakeDone() const;
    bool SentShutdown() const;
    bool ReceivedShutdown() const;
    int SystemError() const;
    std::uint32_t VerifyFlags() const;
    const char* Version() const;
    const char* Cipher() const;

private:
    struct State;
    std::unique_ptr<State> state;
};

}

#endif
