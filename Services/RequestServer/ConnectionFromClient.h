/*
 * Copyright (c) 2018-2020, Andreas Kling <andreas@ladybird.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Badge.h>
#include <AK/ByteBuffer.h>
#include <AK/HashMap.h>
#include <AK/HashTable.h>
#include <AK/Optional.h>
#include <AK/Time.h>
#include <AK/Vector.h>
#include <LibCore/AnonymousBuffer.h>
#include <LibCore/Timer.h>
#include <LibHTTP/Cache/CacheMode.h>
#include <LibHTTP/Cache/DiskCacheSettings.h>
#include <LibHTTP/Cache/Utilities.h>
#include <LibHTTP/Forward.h>
#include <LibHTTP/Proxy.h>
#include <LibIPC/ConnectionFromClient.h>
#include <LibRequests/RequestTransferLease.h>
#include <LibRequests/WebSocket.h>
#include <LibWebSocket/WebSocket.h>
#include <RequestServer/Forward.h>
#include <RequestServer/IsPrivate.h>
#include <RequestServer/RequestClientEndpoint.h>
#include <RequestServer/RequestServerEndpoint.h>
#include <RequestServer/SiteBinding.h>

namespace RequestServer {

// Cap on an AIA response: these carry one DER or PKCS#7 certificate bundle, never anything large.
constexpr inline size_t max_aia_response_size = 64 * KiB;

class ConnectionFromClient;

struct AIAFetch {
    AK_ALLOC_WITH_KMALLOC;

    ConnectionFromClient* client { nullptr };
    ByteString url;
    ByteBuffer body;
    Vector<u64> request_ids;
    curl_slist* resolve_list { nullptr };
};

// Diagnostics hook shared with the control connection; only does anything under REQUESTSERVER_WIRE_DEBUG.
void note_event_tick(StringView label);

// What the connection pool knows an origin by: its scheme, host and port.
ByteString connection_pool_key(URL::URL const&);

// A libcurl multi handle, driven by the event loop. Its transfers share one connection pool.
class CurlMulti : public RefCounted<CurlMulti> {
    AK_MAKE_NONCOPYABLE(CurlMulti);
    AK_MAKE_NONMOVABLE(CurlMulti);

public:
    static NonnullRefPtr<CurlMulti> create();
    ~CurlMulti();

    void* handle() const { return m_handle; }

    // What the transfers in the pool found out about origins, see ConnectionFromClient::origin_multiplexes() and
    // ConnectionFromClient::has_warm_connection().
    HashMap<ByteString, bool> origins_multiplexing;
    HashMap<ByteString, MonotonicTime> warm_connections;

    // The connections of the pool to an origin known to speak HTTP/1.x, which serve one transfer at a time, see
    // Request::start_transfer(). The counts are what the pool's transfers found out, and may be off when a server
    // closes a connection: that only costs a transfer the connection it would otherwise have made.
    static constexpr size_t maximum_host_connections = 6;
    struct HTTP1Origin {
        size_t busy_connections { 0 };
        size_t idle_connections { 0 };
        size_t pending_connections { 0 };
        Vector<Request*> waiting_transfers;
    };
    HashMap<ByteString, HTTP1Origin> http1_origins;

    // An idle connection to the origin, or none if the connection that became ready is gone, goes to the transfer that
    // waited longest for one, if any.
    void offer_http1_connection(ByteString const& origin_key, bool connection_is_idle);

private:
    CurlMulti();

    static int on_socket_callback(void*, int sockfd, int what, void* user_data, void*);
    static int on_timeout_callback(void*, long timeout_ms, void* user_data);

    void* m_handle { nullptr };
    RefPtr<Core::Timer> m_timer;
    Optional<MonotonicTime> m_timer_due_at;
    HashMap<int, NonnullRefPtr<Core::Notifier>> m_read_notifiers;
    HashMap<int, NonnullRefPtr<Core::Notifier>> m_write_notifiers;
};

class ConnectionFromClient final
    : public IPC::ConnectionFromClient<RequestClientEndpoint, RequestServerEndpoint> {
    C_OBJECT(ConnectionFromClient);

    friend class ControlConnectionFromClient;

public:
    using ConnectionMap = HashMap<int, NonnullRefPtr<ConnectionFromClient>>;

    struct RequestTransferLease {
        NonnullRefPtr<ConnectionFromClient> owner;
        u64 request_id { 0 };
        // The bound client that may adopt the request, until it does or disconnects.
        Optional<int> adopter_client_id {};
    };

    using RequestTransferLeaseMap = HashMap<Requests::RequestTransferLeaseKey, RequestTransferLease>;

    ~ConnectionFromClient() override;

    virtual void die() override;

    bool websocket_retrieved_http_cookie(Badge<ControlConnectionFromClient>, u64 websocket_id, u64 cookie_request_id, String cookie);

    IsPrivate is_private() const { return m_is_private; }

    // Lets a bound client make requests for documents of frame_site under a top-level document of top_level_site. A
    // frame site of nothing stands for documents with opaque origins.
    void bind_to_site(Badge<ControlConnectionFromClient>, Utf16String const& top_level_site, Optional<Utf16String> const& frame_site);

    void start_revalidation_request(Badge<Request>, HTTP::NetworkIsolationKey, ByteString method, URL::URL, NonnullRefPtr<HTTP::HeaderList> request_headers, ByteBuffer request_body, HTTP::Cookie::IncludeCredentials, HTTP::Cookie::SameSiteContext);
    void request_complete(Badge<Request>, Request const&);

    // Whether this client's connection pool recently got a connection to the origin of the given URL that a new request
    // to it could most likely use without having to open another one: one that carried an HTTP/2 transfer, which more
    // requests can be multiplexed over, or one that a preconnect left for the next request.
    void note_warm_connection(Badge<Request>, URL::URL const&);
    bool has_warm_connection(URL::URL const&) const;

    // Whether the origin of the given URL multiplexes requests over one connection, as far as this client's transfers,
    // or the process making them, found out.
    void note_origin_multiplexes(URL::URL const&, bool multiplexes);
    Optional<bool> origin_multiplexes(URL::URL const&) const;

    void fetch_aia_intermediate(Badge<Request>, ByteString const& url, u64 for_request_id);

    CurlMulti& fetch_curl() { return *m_fetch_curl; }
    // Makes a connection to the origin of the URL for a transfer that waits for one, see Request::start_transfer().
    void connect_for_waiting_http1_transfer(Badge<Request>, URL::URL const&);

private:
    ConnectionFromClient(NonnullOwnPtr<IPC::Transport>, int client_id, IsPrivate, SiteBinding, ConnectionMap&, RequestTransferLeaseMap&, Optional<HTTP::DiskCache&>);

    bool may_use_network_isolation_key(HTTP::NetworkIsolationKey const&, URL::URL const* request_url = nullptr) const;

    virtual Messages::RequestServer::IsSupportedProtocolResponse is_supported_protocol(ByteString) override;
    virtual Messages::RequestServer::GetClientIdResponse get_client_id() override;
    virtual void start_request(u64 request_id, ByteString, URL::URL, Vector<HTTP::Header>, ByteBuffer, HTTP::CacheMode, Optional<HTTP::NetworkIsolationKey>, HTTP::Cookie::IncludeCredentials, bool create_transfer_lease, Optional<u32> address_selection_hint, bool notify_on_cache_miss, u64 originating_page_id, HTTP::Cookie::SameSiteContext, AK::Duration requested_at) override;
    virtual void adopt_request(int source_client_id, u64 source_request_id, u64 target_request_id, bool preserve_transfer_lease, Optional<int> owner_client_id) override;
    virtual void release_request_transfer_lease(int source_client_id, u64 source_request_id) override;
    virtual Messages::RequestServer::StopRequestResponse stop_request(u64 request_id) override;
    virtual Messages::RequestServer::ExportRequestResponse export_request(u64 request_id) override;
    virtual void import_request(u64 request_id, Requests::ExportedRequest, bool create_transfer_lease) override;
    virtual void ensure_connection(u64 request_id, URL::URL url, ::RequestServer::CacheLevel cache_level, Optional<bool> origin_multiplexes) override;
    virtual void resolve_host(u64 lookup_id, ByteString host) override;

    virtual void websocket_connect(u64 websocket_id, URL::URL, Optional<HTTP::NetworkIsolationKey>, ByteString, Vector<ByteString>, Vector<ByteString>, Vector<HTTP::Header>, u64 originating_page_id, HTTP::Cookie::SameSiteContext) override;
    virtual void websocket_send(u64 websocket_id, bool, ByteBuffer) override;
    virtual void websocket_send_shared(u64 websocket_id, bool, Core::AnonymousBuffer) override;
    virtual void websocket_close(u64 websocket_id, u16, ByteString) override;

    friend class CurlMulti;

    bool is_live_request_id(u64 request_id) const;
    void cancel_owned_work();
    // Hands the transfers that a multi handle finished to whoever made them, whichever client that is.
    static void drain_completed_transfers(void* multi_handle);
    void complete_aia_fetch(void* easy_handle, int result_code);
    void fail_websocket(u64 websocket_id, Requests::WebSocket::Error);
    size_t websocket_count() const;
    size_t total_websocket_count() const;
    void connect_websocket(u64 websocket_id, u64 originating_page_id, URL::URL, ByteString origin, Vector<ByteString> protocols, Vector<ByteString> extensions, Vector<HTTP::Header> request_headers);
    void look_up_websocket_host(u64 websocket_id, u64 originating_page_id, URL::URL, ByteString origin, Vector<ByteString> protocols, Vector<ByteString> extensions, Vector<HTTP::Header> additional_request_headers, Optional<HTTP::Proxy>);
    void open_websocket(u64 websocket_id, u64 originating_page_id, URL::URL, ByteString origin, Vector<ByteString> protocols, Vector<ByteString> extensions, Vector<HTTP::Header> additional_request_headers, Optional<HTTP::Proxy>, RefPtr<DNS::LookupResult const>);

    IsPrivate m_is_private { IsPrivate::No };

    SiteBinding m_site_binding { SiteBinding::Bound };
    struct BoundSite {
        Utf16String top_level_site;
        Utf16String frame_site;

        bool operator==(BoundSite const&) const = default;
    };
    struct BoundSiteTraits : public DefaultTraits<BoundSite> {
        static unsigned hash(BoundSite const& site) { return pair_int_hash(site.top_level_site.hash(), site.frame_site.hash()); }
    };

    // NB: Bindings are only ever added, for the life of the client. See WebView::RequestServerSiteBindings.
    HashTable<Utf16String> m_bound_top_level_sites;
    HashTable<BoundSite, BoundSiteTraits> m_bound_sites;

    ConnectionMap& m_connections;
    RequestTransferLeaseMap& m_request_transfer_leases;
    Optional<HTTP::DiskCache&> m_disk_cache;

    NonnullRefPtr<CurlMulti> m_fetch_curl;
    NonnullRefPtr<CurlMulti> m_websocket_curl;

    HashMap<u64, NonnullOwnPtr<Request>> m_active_requests;
    HashMap<u64, NonnullOwnPtr<Request>> m_active_revalidation_requests;
    HashMap<u64, NonnullOwnPtr<Request>> m_http1_connects;
    u64 m_next_http1_connect_id { 0 };
    void look_up_aia_host(ByteString const& url, ByteString const& fetch_url, ByteString const& host, u16 port, Optional<HTTP::Proxy>);
    void start_aia_fetch(ByteString const& url, ByteString const& fetch_url, Optional<HTTP::Proxy>, Optional<ByteString> resolve_entry);
    void abandon_aia_lookup(ByteString const& url);

    HashMap<void*, NonnullOwnPtr<AIAFetch>> m_aia_fetches;
    // AIA URLs whose DNS lookup is still outstanding, mapped to the requests waiting on them. Keeps a second
    // request asking for the same URL from starting a duplicate lookup before m_aia_fetches has an entry.
    HashMap<ByteString, Vector<u64>> m_pending_aia_lookups;
    HashTable<u64> m_pending_websockets;

    struct WebSocketCookieRequest {
        u64 cookie_request_id { 0 };
        Function<void(String)> continuation;
    };
    HashMap<u64, WebSocketCookieRequest> m_websocket_cookie_requests;
    HashMap<u64, RefPtr<WebSocket::WebSocket>> m_websockets;

    NonnullRefPtr<Resolver> m_resolver;

    u64 m_next_revalidation_request_id { 0 };

    Optional<MonotonicTime> m_burst_window_started_at;
    u64 m_requests_in_burst_window { 0 };
};

constexpr inline uintptr_t websocket_private_tag = 0x1;
constexpr inline uintptr_t aia_fetch_private_tag = 0x2;

}
