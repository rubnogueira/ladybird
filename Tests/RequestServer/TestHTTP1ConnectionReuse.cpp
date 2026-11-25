/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/ByteString.h>
#include <AK/Time.h>
#include <LibCore/EventLoop.h>
#include <LibCore/Socket.h>
#include <LibCore/TCPServer.h>
#include <LibCore/Timer.h>
#include <LibHTTP/Cache/DiskCache.h>
#include <LibIPC/Transport.h>
#include <LibTest/TestCase.h>
#include <LibURL/Parser.h>
#include <RequestServer/CURL.h>
#include <RequestServer/ConnectionFromClient.h>

// The UI process picks the IDs of RequestServer's clients.
static int s_last_client_id { 0 };

namespace {

// An HTTP/1.1 server that keeps its connections alive, and answers requests for /slow only after a while.
class KeepAliveServer {
public:
    static constexpr auto slow_response_delay = AK::Duration::from_milliseconds(300);

    KeepAliveServer()
    {
        m_server = MUST(Core::TCPServer::try_create());
        MUST(m_server->listen(IPv4Address { 127, 0, 0, 1 }, 0));
        m_server->on_ready_to_accept = [this] {
            auto socket = MUST(m_server->accept());
            MUST(socket->set_blocking(false));
            auto connection = make<Connection>(move(socket));
            auto* connection_ptr = connection.ptr();
            connection_ptr->socket->on_ready_to_read = [this, connection_ptr] { on_ready_to_read(*connection_ptr); };
            m_connections.append(move(connection));
        };
    }

    URL::URL url_for_path(StringView path) const
    {
        return URL::Parser::basic_parse(ByteString::formatted("http://127.0.0.1:{}{}", *m_server->local_port(), path)).release_value();
    }

    size_t connection_count() const { return m_connections.size(); }

private:
    struct Connection {
        AK_ALLOC_WITH_KMALLOC;

        explicit Connection(NonnullOwnPtr<Core::TCPSocket> socket)
            : socket(move(socket))
        {
        }

        NonnullOwnPtr<Core::TCPSocket> socket;
        ByteBuffer request;
        RefPtr<Core::Timer> timer;
    };

    void on_ready_to_read(Connection& connection)
    {
        auto buffer = MUST(ByteBuffer::create_uninitialized(4096));
        auto bytes = connection.socket->read_some(buffer);
        if (bytes.is_error() || bytes.value().is_empty()) {
            connection.socket->on_ready_to_read = nullptr;
            return;
        }
        MUST(connection.request.try_append(bytes.value()));

        auto request = StringView { connection.request };
        auto end_of_head = request.find("\r\n\r\n"sv);
        if (!end_of_head.has_value())
            return;
        auto is_slow = request.starts_with("GET /slow "sv);
        connection.request.clear();

        auto respond = [&connection] {
            auto body = "hello"sv;
            auto response = ByteString::formatted(
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: {}\r\n"
                "Cache-Control: no-store\r\n"
                "\r\n"
                "{}",
                body.length(), body);
            MUST(connection.socket->write_until_depleted(response.bytes()));
        };
        if (!is_slow) {
            respond();
            return;
        }
        connection.timer = Core::Timer::create_single_shot(slow_response_delay, move(respond));
        connection.timer->start();
    }

    RefPtr<Core::TCPServer> m_server;
    Vector<NonnullOwnPtr<Connection>> m_connections;
};

class TestClient {
public:
    TestClient()
    {
        static bool libcurl_initialized = [] {
            MUST(RequestServer::initialize_libcurl());
            return true;
        }();
        (void)libcurl_initialized;

        auto pair = MUST(IPC::Transport::create_paired());
        m_remote_transport = MUST(pair.remote_handle.create_transport());
        m_connection = RequestServer::ConnectionFromClient::construct(
            move(pair.local), ++s_last_client_id, RequestServer::IsPrivate::No, RequestServer::SiteBinding::Unrestricted,
            m_connections, m_request_transfer_leases, Optional<HTTP::DiskCache&> {});
    }

    ~TestClient()
    {
        if (m_connection->is_open())
            m_connection->shutdown();
    }

    void start(u64 request_id, URL::URL url)
    {
        auto message = make<Messages::RequestServer::StartRequest>(request_id, ByteString { "GET" }, move(url), Vector<HTTP::Header> {}, ByteBuffer {}, HTTP::CacheMode::Default, Optional<HTTP::NetworkIsolationKey> {}, HTTP::Cookie::IncludeCredentials::No, false, Optional<u32> {}, false, 0, HTTP::Cookie::SameSiteContext {}, AK::Duration::from_nanoseconds(MonotonicTime::now().nanoseconds()));
        VERIFY(!MUST(static_cast<RequestServerEndpoint::Stub&>(*m_connection).handle(move(message))));
    }

    void stop(u64 request_id)
    {
        auto message = make<Messages::RequestServer::StopRequest>(request_id);
        VERIFY(MUST(static_cast<RequestServerEndpoint::Stub&>(*m_connection).handle(move(message))));
    }

    // Whether the requests all finished without a network error in time.
    bool wait_for(Vector<u64> const& request_ids, AK::Duration budget = AK::Duration::from_seconds(10))
    {
        auto deadline = MonotonicTime::now() + budget;
        while (MonotonicTime::now() < deadline) {
            m_event_loop.pump(Core::EventLoop::WaitMode::PollForEvents);
            drain_client_messages();
            if (all_of(request_ids, [&](auto request_id) { return m_finished.contains(request_id); }))
                return all_of(request_ids, [&](auto request_id) { return !m_finished.get(request_id)->has_value(); });
        }
        return false;
    }

    void pump_for(AK::Duration duration)
    {
        auto deadline = MonotonicTime::now() + duration;
        while (MonotonicTime::now() < deadline) {
            m_event_loop.pump(Core::EventLoop::WaitMode::PollForEvents);
            drain_client_messages();
        }
    }

private:
    void drain_client_messages()
    {
        (void)m_remote_transport->read_as_many_messages_as_possible_without_blocking([&](auto&& raw_message) {
            auto message = MUST(RequestClientEndpoint::decode_message(raw_message.bytes.bytes(), raw_message.attachments));
            if (message->message_id() == Messages::RequestClient::RequestStarted::static_message_id()) {
                auto& started = static_cast<Messages::RequestClient::RequestStarted&>(*message);
                auto response_socket = MUST(Core::LocalSocket::adopt_fd(started.fd().take_fd()));
                response_socket->set_notifications_enabled(false);
                m_response_sockets.set(started.request_id(), move(response_socket));
            }
            if (message->message_id() == Messages::RequestClient::RequestFinished::static_message_id()) {
                auto& finished = static_cast<Messages::RequestClient::RequestFinished&>(*message);
                m_finished.set(finished.request_id(), finished.network_error());
            }
        });

        auto buffer = MUST(ByteBuffer::create_uninitialized(4 * KiB));
        for (auto& response_socket : m_response_sockets)
            (void)response_socket.value->read_some(buffer);
    }

    Core::EventLoop m_event_loop;
    RequestServer::ConnectionFromClient::ConnectionMap m_connections;
    RequestServer::ConnectionFromClient::RequestTransferLeaseMap m_request_transfer_leases;
    OwnPtr<IPC::Transport> m_remote_transport;
    RefPtr<RequestServer::ConnectionFromClient> m_connection;
    HashMap<u64, NonnullOwnPtr<Core::LocalSocket>> m_response_sockets;
    HashMap<u64, Optional<Requests::NetworkError>> m_finished;
};

}

// A transfer to an origin known to speak HTTP/1.x waits for a connection while another holds the only one. It gets the
// connection made for it, or the other one once that is idle, and the connections it doesn't take serve later ones.
TEST_CASE(transfers_that_wait_for_an_http1_connection_all_complete)
{
    TestClient client;
    KeepAliveServer server;

    // The first response tells RequestServer that the origin speaks HTTP/1.1, and leaves its connection idle.
    client.start(1, server.url_for_path("/first"sv));
    EXPECT(client.wait_for({ 1 }));
    EXPECT_EQ(server.connection_count(), 1u);

    client.start(2, server.url_for_path("/slow"sv));
    for (u64 request_id = 3; request_id <= 6; ++request_id)
        client.start(request_id, server.url_for_path("/fast"sv));
    EXPECT(client.wait_for({ 2, 3, 4, 5, 6 }));
    EXPECT(server.connection_count() <= 6u);

    // Every connection is idle again, so these need none of their own.
    auto connections = server.connection_count();
    for (u64 request_id = 7; request_id <= 9; ++request_id)
        client.start(request_id, server.url_for_path("/fast"sv));
    EXPECT(client.wait_for({ 7, 8, 9 }));
    EXPECT_EQ(server.connection_count(), connections);
}

// A waiting transfer that is stopped gives up its place, and the connection made for it serves the next transfer.
TEST_CASE(a_transfer_stopped_while_it_waits_for_an_http1_connection_leaves_none_behind)
{
    TestClient client;
    KeepAliveServer server;

    client.start(1, server.url_for_path("/first"sv));
    EXPECT(client.wait_for({ 1 }));

    client.start(2, server.url_for_path("/slow"sv));
    client.start(3, server.url_for_path("/fast"sv));
    client.stop(3);
    client.pump_for(AK::Duration::from_milliseconds(50));

    client.start(4, server.url_for_path("/fast"sv));
    EXPECT(client.wait_for({ 2, 4 }));
    EXPECT_EQ(server.connection_count(), 2u);
}
