#include "prx/libSceLibreSsl/include/SslInternal.hpp"
#include "prx/libc/include/Api.hpp"
#include "prx/libc/include/General.hpp"
#include <atomic>
#include <cstddef>
#include <cstdint>

static_assert(sizeof(LibreSslBioMethod) == 80);
static_assert(offsetof(LibreSslBioMethod, name) == 8);
static_assert(sizeof(LibreSslBio) == 104);
static_assert(offsetof(LibreSslBio, callback) == 8);
static_assert(offsetof(LibreSslBio, init) == 24);
static_assert(offsetof(LibreSslBio, shutdown) == 28);
static_assert(offsetof(LibreSslBio, flags) == 32);
static_assert(offsetof(LibreSslBio, retryReason) == 36);
static_assert(offsetof(LibreSslBio, num) == 40);
static_assert(offsetof(LibreSslBio, pointer) == 48);
static_assert(offsetof(LibreSslBio, nextBio) == 56);
static_assert(offsetof(LibreSslBio, previousBio) == 64);
static_assert(offsetof(LibreSslBio, references) == 72);
static_assert(offsetof(LibreSslBio, numRead) == 80);
static_assert(offsetof(LibreSslBio, numWrite) == 88);
static_assert(offsetof(LibreSslBio, exData) == 96);

namespace {

int APS5_VABI SocketWrite_nid_no_patch(LibreSslBio*, const char*, int) {
    NotImplemented_nid_no_patch("BIO_s_socket write callback");
}

int APS5_VABI SocketRead_nid_no_patch(LibreSslBio*, char*, int) {
    NotImplemented_nid_no_patch("BIO_s_socket read callback");
}

int APS5_VABI SocketPuts_nid_no_patch(LibreSslBio*, const char*) {
    NotImplemented_nid_no_patch("BIO_s_socket puts callback");
}

std::int64_t APS5_VABI SocketControl_nid_no_patch(LibreSslBio*, int, std::int64_t, void*) {
    NotImplemented_nid_no_patch("BIO_s_socket control callback");
}

int APS5_VABI SocketCreate_nid_no_patch(LibreSslBio*) {
    NotImplemented_nid_no_patch("BIO_s_socket create callback");
}

int APS5_VABI SocketDestroy_nid_no_patch(LibreSslBio*) {
    NotImplemented_nid_no_patch("BIO_s_socket destroy callback");
}

const LibreSslBioMethod socketMethod{
    SslLayout::BioTypeSocket,
    "socket",
    reinterpret_cast<void*>(SocketWrite_nid_no_patch),
    reinterpret_cast<void*>(SocketRead_nid_no_patch),
    reinterpret_cast<void*>(SocketPuts_nid_no_patch),
    nullptr,
    reinterpret_cast<void*>(SocketControl_nid_no_patch),
    reinterpret_cast<void*>(SocketCreate_nid_no_patch),
    reinterpret_cast<void*>(SocketDestroy_nid_no_patch),
    nullptr};

void FreeBio(LibreSslBio* bio) {
    if (std::atomic_ref<int>(bio->references).fetch_sub(1) - 1 > 0) return;
    if (bio->callback) NotImplemented_nid_no_patch("BIO_free: BIO callback");
    if (bio->method != &socketMethod) NotImplemented_nid_no_patch("BIO_free: BIO type other than a socket");
    if (bio->shutdown && bio->init) NotImplemented_nid_no_patch("BIO_free: closing the descriptor of a socket BIO");
    if (bio->exData.stack) NotImplemented_nid_no_patch("BIO_free: BIO ex_data");
    free_nid_postfix(bio);
}

}

extern "C" {

LibreSslBio* LibreSslNewSocketBio_nid_no_patch(int descriptor) {
    auto* bio = static_cast<LibreSslBio*>(calloc_nid_postfix(1, sizeof(LibreSslBio)));
    if (!bio) return nullptr;
    bio->method = &socketMethod;
    bio->references = 1;
    bio->init = 1;
    bio->shutdown = 0;
    bio->num = descriptor;
    return bio;
}

void LibreSslFreeBioChain_nid_no_patch(LibreSslBio* bio) {
    while (bio) {
        LibreSslBio* current = bio;
        const int references = current->references;
        bio = bio->nextBio;
        FreeBio(current);
        if (references > 1) break;
    }
}

int LibreSslBioDescriptor_nid_no_patch(const LibreSslBio* bio) {
    for (const LibreSslBio* current = bio; current; current = current->nextBio) {
        if (!current->method || !(current->method->type & SslLayout::BioTypeDescriptor)) continue;
        if (current->method != &socketMethod) NotImplemented_nid_no_patch("BIO_get_fd: BIO type other than a socket");
        return current->init ? current->num : -1;
    }
    return -1;
}

bool LibreSslIsSocketBio_nid_no_patch(const LibreSslBio* bio) {
    return bio && bio->method == &socketMethod;
}

}
