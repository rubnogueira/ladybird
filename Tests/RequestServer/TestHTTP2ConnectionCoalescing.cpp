/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Atomic.h>
#include <AK/ByteBuffer.h>
#include <AK/ByteString.h>
#include <AK/Optional.h>
#include <AK/Vector.h>
#include <LibTest/TestCase.h>
#include <LibThreading/Thread.h>
#include <RequestServer/CURL.h>

#include <arpa/inet.h>
#include <curl/curl.h>
#include <netinet/in.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef LIBCURL_HAS_COALESCE

// Generated certificate fixtures (EC/prime256v1, fixed validity 2020-2050):
// - CA: "Coalescing Test CA", the only trusted root.
// - SHARED: issued by CA to a.test and b.test.
// - A_ONLY: issued by CA to a.test.
static constexpr auto ca_certificate = R"PEM(-----BEGIN CERTIFICATE-----
MIIBgTCCASagAwIBAgIUQCZnQq0Oc7vGYiY21Y60u/DHs/EwCgYIKoZIzj0EAwIw
HTEbMBkGA1UEAwwSQ29hbGVzY2luZyBUZXN0IENBMCAXDTIwMDEwMTAwMDAwMFoY
DzIwNTAwMTAxMDAwMDAwWjAdMRswGQYDVQQDDBJDb2FsZXNjaW5nIFRlc3QgQ0Ew
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQgFxrHktNUiw1hSN8ueSBrAXuiGPnL
t/pxvzwuyqbpAlkCld8vr/HZAZjzZBcGVslYvznE8q9/KDt8I3Uhqk8co0IwQDAd
BgNVHQ4EFgQU32/ON4lR2CAGuXNh/x6y+1InmaQwDwYDVR0TAQH/BAUwAwEB/zAO
BgNVHQ8BAf8EBAMCAgQwCgYIKoZIzj0EAwIDSQAwRgIhAOdx0M/nKd3vSMEjZuty
R2evnOyKOzcY9a4xL4lwnLucAiEA//4Fj4I5Ttv6FV3eSbbg8SjeNL7ScJQRN9oS
1YhTl18=
-----END CERTIFICATE-----)PEM"sv;
static constexpr auto shared_certificate = R"PEM(-----BEGIN CERTIFICATE-----
MIIBUTCB96ADAgECAghum8rW2oFKiDAKBggqhkjOPQQDAjAdMRswGQYDVQQDDBJD
b2FsZXNjaW5nIFRlc3QgQ0EwIBcNMjAwMTAxMDAwMDAwWhgPMjA1MDAxMDEwMDAw
MDBaMBExDzANBgNVBAMMBmEudGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
BMTXGffphfqBnkviyJtBQHXxU4Y45gL/FVr/1/dNDwImrGN2hJycvAaFm3eu1FmN
eQ/oMsStBHyScoGP7WODH4KjKzApMBkGA1UdEQQSMBCCBmEudGVzdIIGYi50ZXN0
MAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwIDSQAwRgIhANNC1YkFRJbdtbNtMYe8
JOu78TcgNlohDBsf3+h4PdGkAiEA8wj5baCeRHDHZCkVc6nm0Q9+mTa2TudYlqFN
6bULzhs=
-----END CERTIFICATE-----)PEM"sv;
static constexpr auto shared_key = R"PEM(-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9uaC+nMXcG4tafEh
eNu9DPHRlRJsZokLyH8GXt4aTEChRANCAATE1xn36YX6gZ5L4sibQUB18VOGOOYC
/xVa/9f3TQ8CJqxjdoScnLwGhZt3rtRZjXkP6DLErQR8knKBj+1jgx+C
-----END PRIVATE KEY-----)PEM"sv;
static constexpr auto a_only_certificate = R"PEM(-----BEGIN CERTIFICATE-----
MIIBSDCB8KADAgECAgkA+6IH7bn7cF0wCgYIKoZIzj0EAwIwHTEbMBkGA1UEAwwS
Q29hbGVzY2luZyBUZXN0IENBMCAXDTIwMDEwMTAwMDAwMFoYDzIwNTAwMTAxMDAw
MDAwWjARMQ8wDQYDVQQDDAZhLnRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AAQ4CFSVN4B84ypCBCwX8CBlfJGOVdex+UmAZWRYq6T3LlQBBQ9s5ixohMdUbg1z
BbH/5Yusl3sZFdTgE4daZ+gfoyMwITARBgNVHREECjAIggZhLnRlc3QwDAYDVR0T
AQH/BAIwADAKBggqhkjOPQQDAgNHADBEAiAWFvATyMk7IWZ0rM1nIqhVJIuTFzOC
C5OsUM8EfZgWJQIgQHOWZEJg4i/5jaTm2UckwxVTGJLfl9wzuB36MW2E1MU=
-----END CERTIFICATE-----)PEM"sv;
static constexpr auto a_only_key = R"PEM(-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQggop39oRBRIUOtdOL
sGmsAEQgg1suUGtfSZvMjUwbNzGhRANCAAQ4CFSVN4B84ypCBCwX8CBlfJGOVdex
+UmAZWRYq6T3LlQBBQ9s5ixohMdUbg1zBbH/5Yusl3sZFdTgE4daZ+gf
-----END PRIVATE KEY-----)PEM"sv;

namespace {

constexpr auto client_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"sv;
constexpr u8 frame_type_headers = 0x1;
constexpr u8 frame_type_settings = 0x4;
constexpr u8 frame_type_goaway = 0x7;
constexpr u8 flag_ack = 0x1;
constexpr u8 flag_end_stream = 0x1;
constexpr u8 flag_end_headers = 0x4;

void append_frame(ByteBuffer& buffer, u8 type, u8 flags, u32 stream_id, ReadonlyBytes payload)
{
    u8 header[9] = {
        static_cast<u8>(payload.size() >> 16), static_cast<u8>(payload.size() >> 8), static_cast<u8>(payload.size()),
        type, flags,
        static_cast<u8>(stream_id >> 24), static_cast<u8>(stream_id >> 16), static_cast<u8>(stream_id >> 8), static_cast<u8>(stream_id)
    };
    buffer.append(header, sizeof(header));
    buffer.append(payload);
}

// An HTTPS server on a loopback port that speaks just enough HTTP/2 to answer each request with an empty response. Each
// connection is served by a thread of its own, so that a client can hold several at once.
class HTTP2TLSServer {
public:
    // Answers this stream of each connection made with this server name with 421 (Misdirected Request).
    struct Misdirection {
        StringView server_name;
        u32 stream_id { 0 };
    };

    enum class Listen {
        IPv4,
        IPv4AndIPv6,
    };

    HTTP2TLSServer(StringView certificate, StringView key, Optional<Misdirection> misdirection = {}, Listen listen = Listen::IPv4)
        : m_misdirection(misdirection)
    {
        // A client that rejects the certificate closes the connection mid-handshake.
        signal(SIGPIPE, SIG_IGN);

        m_context = SSL_CTX_new(TLS_server_method());
        VERIFY(m_context);
        auto* certificate_bio = BIO_new_mem_buf(certificate.characters_without_null_termination(), static_cast<int>(certificate.length()));
        auto* x509 = PEM_read_bio_X509(certificate_bio, nullptr, nullptr, nullptr);
        BIO_free(certificate_bio);
        auto* key_bio = BIO_new_mem_buf(key.characters_without_null_termination(), static_cast<int>(key.length()));
        auto* private_key = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
        BIO_free(key_bio);
        VERIFY(x509 && private_key);
        VERIFY(SSL_CTX_use_certificate(m_context, x509) == 1);
        VERIFY(SSL_CTX_use_PrivateKey(m_context, private_key) == 1);
        X509_free(x509);
        EVP_PKEY_free(private_key);
        SSL_CTX_set_alpn_select_cb(m_context, select_http2, nullptr);

        if (listen == Listen::IPv4AndIPv6) {
            m_socket = socket(AF_INET6, SOCK_STREAM, 0);
            VERIFY(m_socket >= 0);
            int v6_only = 0;
            VERIFY(setsockopt(m_socket, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only, sizeof(v6_only)) == 0);
            sockaddr_in6 address {};
            address.sin6_family = AF_INET6;
            address.sin6_addr = in6addr_any;
            VERIFY(bind(m_socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
            socklen_t length = sizeof(address);
            VERIFY(getsockname(m_socket, reinterpret_cast<sockaddr*>(&address), &length) == 0);
            m_port = ntohs(address.sin6_port);
        } else {
            m_socket = socket(AF_INET, SOCK_STREAM, 0);
            VERIFY(m_socket >= 0);
            sockaddr_in address {};
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            VERIFY(bind(m_socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
            socklen_t length = sizeof(address);
            VERIFY(getsockname(m_socket, reinterpret_cast<sockaddr*>(&address), &length) == 0);
            m_port = ntohs(address.sin_port);
        }
        VERIFY(::listen(m_socket, 8) == 0);

        m_accept_thread = Threading::Thread::construct("HTTP2TLSServer"sv, [this] { return accept_connections(); });
        m_accept_thread->start();
    }

    ~HTTP2TLSServer()
    {
        m_stopping.store(true);
        // Wake up accept() with a connection of our own.
        auto wake = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in address {};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(m_port);
        (void)connect(wake, reinterpret_cast<sockaddr*>(&address), sizeof(address));
        (void)m_accept_thread->join();
        close(wake);
        for (auto& thread : m_connection_threads)
            (void)thread->join();
        close(m_socket);
        SSL_CTX_free(m_context);
    }

    u16 port() const { return m_port; }
    size_t connection_count() const { return m_connection_count.load(); }

private:
    static int select_http2(SSL*, unsigned char const** out, unsigned char* out_length, unsigned char const* in, unsigned int in_length, void*)
    {
        static constexpr unsigned char http2[] = { 2, 'h', '2' };
        if (SSL_select_next_proto(const_cast<unsigned char**>(out), out_length, http2, sizeof(http2), in, in_length) != OPENSSL_NPN_NEGOTIATED)
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        return SSL_TLSEXT_ERR_OK;
    }

    intptr_t accept_connections()
    {
        while (true) {
            auto connection = accept(m_socket, nullptr, nullptr);
            if (connection < 0)
                continue;
            if (m_stopping.load()) {
                close(connection);
                return 0;
            }
            m_connection_count.fetch_add(1);

            timeval timeout { 10, 0 };
            VERIFY(setsockopt(connection, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
            VERIFY(setsockopt(connection, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
            auto thread = Threading::Thread::construct("HTTP2TLSConnection"sv, [this, connection] {
                auto* ssl = SSL_new(m_context);
                SSL_set_fd(ssl, connection);
                if (SSL_accept(ssl) == 1)
                    serve(ssl);
                SSL_free(ssl);
                close(connection);
                return static_cast<intptr_t>(0);
            });
            thread->start();
            m_connection_threads.append(move(thread));
        }
    }

    void serve(SSL* ssl)
    {
        auto const* server_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
        auto misdirected_stream_id = m_misdirection.has_value() && server_name && m_misdirection->server_name == StringView { server_name, strlen(server_name) }
            ? m_misdirection->stream_id
            : 0;

        ByteBuffer settings;
        append_frame(settings, frame_type_settings, 0, 0, {});
        if (!write(ssl, settings))
            return;

        ByteBuffer received;
        size_t offset = 0;
        while (true) {
            u8 chunk[4096];
            auto count = SSL_read(ssl, chunk, sizeof(chunk));
            if (count <= 0)
                return;
            received.append(chunk, count);
            if (offset == 0) {
                if (received.size() < client_preface.length())
                    continue;
                offset = client_preface.length();
            }

            ByteBuffer response;
            while (received.size() >= offset + 9) {
                auto length = (received[offset] << 16) | (received[offset + 1] << 8) | received[offset + 2];
                if (received.size() < offset + 9 + length)
                    break;
                auto type = received[offset + 3];
                auto flags = received[offset + 4];
                u32 stream_id = ((received[offset + 5] & 0x7f) << 24) | (received[offset + 6] << 16) | (received[offset + 7] << 8) | received[offset + 8];
                offset += 9 + length;

                if (type == frame_type_goaway)
                    return;
                if (type == frame_type_settings && !(flags & flag_ack)) {
                    append_frame(response, frame_type_settings, flag_ack, 0, {});
                } else if (type == frame_type_headers) {
                    ByteBuffer block;
                    if (stream_id == misdirected_stream_id) {
                        // ":status: 421", a literal field without indexing, named by the static table's ":status".
                        block.append(0x08);
                        block.append(3);
                        block.append("421"sv.bytes());
                    } else {
                        block.append(0x88); // ":status: 200", from the static table.
                    }
                    append_frame(response, frame_type_headers, flag_end_headers | flag_end_stream, stream_id, block);
                }
            }
            if (!response.is_empty() && !write(ssl, response))
                return;
        }
    }

    static bool write(SSL* ssl, ByteBuffer const& bytes)
    {
        return SSL_write(ssl, bytes.data(), static_cast<int>(bytes.size())) == static_cast<int>(bytes.size());
    }

    Optional<Misdirection> m_misdirection;
    SSL_CTX* m_context { nullptr };
    int m_socket { -1 };
    u16 m_port { 0 };
    Atomic<bool> m_stopping { false };
    Atomic<size_t> m_connection_count { 0 };
    RefPtr<Threading::Thread> m_accept_thread;
    Vector<NonnullRefPtr<Threading::Thread>> m_connection_threads;
};

// Makes requests one after another through one multi handle, as RequestServer does, so that they share its connections.
class Client {
public:
    enum class Coalesce {
        No,
        Yes,
    };

    explicit Client(Coalesce coalesce)
        : m_coalesce(coalesce)
    {
        MUST(RequestServer::initialize_libcurl());
        m_multi = curl_multi_init();
        VERIFY(m_multi);
    }

    ~Client()
    {
        curl_multi_cleanup(m_multi);
    }

    struct Result {
        CURLcode code { CURLE_OK };
        long status { 0 };
    };

    Result fetch(HTTP2TLSServer const& server, StringView host, StringView address = "127.0.0.1"sv)
    {
        auto url = ByteString::formatted("https://{}:{}/", host, server.port());
        auto resolve_entry = ByteString::formatted("{}:{}:{}", host, server.port(), address);
        auto* resolve = curl_slist_append(nullptr, resolve_entry.characters());

        curl_blob ca_blob {
            .data = const_cast<char*>(ca_certificate.characters_without_null_termination()),
            .len = ca_certificate.length(),
            .flags = CURL_BLOB_COPY,
        };

        auto* easy = curl_easy_init();
        VERIFY(easy);
        curl_easy_setopt(easy, CURLOPT_URL, url.characters());
        curl_easy_setopt(easy, CURLOPT_RESOLVE, resolve);
        curl_easy_setopt(easy, CURLOPT_CAINFO_BLOB, &ca_blob);
        curl_easy_setopt(easy, CURLOPT_CAPATH, nullptr);
        curl_easy_setopt(easy, CURLOPT_NOPROXY, "*");
        curl_easy_setopt(easy, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
        curl_easy_setopt(easy, CURLOPT_PIPEWAIT, 1L);
        curl_easy_setopt(easy, CURLOPT_COALESCE, m_coalesce == Coalesce::Yes ? 1L : 0L);
        curl_easy_setopt(easy, CURLOPT_TIMEOUT, 10L);
        VERIFY(curl_multi_add_handle(m_multi, easy) == CURLM_OK);

        Result result;
        int running = 1;
        while (running) {
            curl_multi_perform(m_multi, &running);
            int remaining = 0;
            while (auto* message = curl_multi_info_read(m_multi, &remaining)) {
                if (message->msg == CURLMSG_DONE)
                    result.code = message->data.result;
            }
            if (running)
                curl_multi_poll(m_multi, nullptr, 0, 100, nullptr);
        }
        curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &result.status);

        curl_multi_remove_handle(m_multi, easy);
        curl_easy_cleanup(easy);
        curl_slist_free_all(resolve);
        return result;
    }

private:
    Coalesce m_coalesce;
    CURLM* m_multi { nullptr };
};

}

// A request to a host that the certificate of an HTTP/2 connection to another host covers, and that resolves to the
// address that connection is to, goes over that connection, as in other browsers.
TEST_CASE(requests_to_hosts_that_a_certificate_covers_share_a_connection)
{
    HTTP2TLSServer server(shared_certificate, shared_key);
    Client client(Client::Coalesce::Yes);

    auto a = client.fetch(server, "a.test"sv);
    EXPECT_EQ(a.code, CURLE_OK);
    EXPECT_EQ(a.status, 200);
    auto b = client.fetch(server, "b.test"sv);
    EXPECT_EQ(b.code, CURLE_OK);
    EXPECT_EQ(b.status, 200);
    EXPECT_EQ(server.connection_count(), 1u);
}

TEST_CASE(requests_to_different_hosts_share_no_connection_without_coalescing)
{
    HTTP2TLSServer server(shared_certificate, shared_key);
    Client client(Client::Coalesce::No);

    EXPECT_EQ(client.fetch(server, "a.test"sv).status, 200);
    EXPECT_EQ(client.fetch(server, "b.test"sv).status, 200);
    EXPECT_EQ(server.connection_count(), 2u);
}

// The certificate of the connection to a.test doesn't cover b.test, so a request to b.test needs a connection of its
// own, over which the same certificate fails verification.
TEST_CASE(a_connection_is_not_shared_with_a_host_its_certificate_does_not_cover)
{
    HTTP2TLSServer server(a_only_certificate, a_only_key);
    Client client(Client::Coalesce::Yes);

    EXPECT_EQ(client.fetch(server, "a.test"sv).status, 200);
    EXPECT_EQ(client.fetch(server, "b.test"sv).code, CURLE_PEER_FAILED_VERIFICATION);
    EXPECT_EQ(server.connection_count(), 2u);
}

TEST_CASE(a_connection_is_not_shared_with_a_host_that_resolves_elsewhere)
{
    HTTP2TLSServer server(shared_certificate, shared_key, {}, HTTP2TLSServer::Listen::IPv4AndIPv6);
    Client client(Client::Coalesce::Yes);

    EXPECT_EQ(client.fetch(server, "a.test"sv).status, 200);
    EXPECT_EQ(client.fetch(server, "b.test"sv, "[::1]"sv).status, 200);
    EXPECT_EQ(server.connection_count(), 2u);
}

// A server answers a request over a connection to another host with 421 (Misdirected Request) if it won't serve the
// request's host over it. The request goes again over a connection to its own host, and the shared connection is kept
// for the requests to the host it was made to.
TEST_CASE(a_misdirected_request_goes_again_over_a_connection_of_its_own)
{
    // The request to b.test is the second on the connection made to a.test.
    HTTP2TLSServer server(shared_certificate, shared_key, HTTP2TLSServer::Misdirection { "a.test"sv, 3 });
    Client client(Client::Coalesce::Yes);

    EXPECT_EQ(client.fetch(server, "a.test"sv).status, 200);
    auto b = client.fetch(server, "b.test"sv);
    EXPECT_EQ(b.code, CURLE_OK);
    EXPECT_EQ(b.status, 200);
    EXPECT_EQ(server.connection_count(), 2u);

    EXPECT_EQ(client.fetch(server, "a.test"sv).status, 200);
    EXPECT_EQ(server.connection_count(), 2u);
}

#endif
