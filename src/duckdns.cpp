#include "duckdns.hpp"

#include "debug.hpp"
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <sstream>
#include <thread>

namespace cryptex {

namespace beast = boost::beast;
namespace http = beast::http;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

namespace {

std::string join_domains(const std::vector<std::string>& domains) {
    std::ostringstream out;
    for (size_t i = 0; i < domains.size(); ++i) {
        if (i) out << ",";
        out << domains[i];
    }
    return out.str();
}

std::string perform_duckdns_update(const std::vector<std::string>& domains,
                                   const std::string& token) {
    boost::asio::io_context ctx;
    ssl::context ssl_ctx(ssl::context::tls_client);
    ssl_ctx.set_default_verify_paths();

    tcp::resolver resolver(ctx);
    beast::ssl_stream<beast::tcp_stream> stream(ctx, ssl_ctx);
    if (!SSL_set_tlsext_host_name(stream.native_handle(), "www.duckdns.org")) {
        throw std::runtime_error("DuckDNS TLS SNI setup failed");
    }

    auto results = resolver.resolve("www.duckdns.org", "443");
    beast::get_lowest_layer(stream).connect(results);
    stream.handshake(ssl::stream_base::client);

    const auto target = "/update?domains=" + join_domains(domains) +
                        "&token=" + token + "&verbose=true";

    http::request<http::empty_body> req{http::verb::get, target, 11};
    req.set(http::field::host, "www.duckdns.org");
    req.set(http::field::user_agent, "CryptEX-DuckDNS");

    http::write(stream, req);

    beast::flat_buffer buffer;
    http::response<http::string_body> res;
    http::read(stream, buffer, res);

    beast::error_code ec;
    stream.shutdown(ec);
    if (ec == boost::asio::error::eof) ec = {};
    if (ec) throw beast::system_error{ec};

    if (res.result() != http::status::ok) {
        throw std::runtime_error("DuckDNS update failed HTTP " +
                                 std::to_string(static_cast<unsigned>(res.result_int())));
    }
    return res.body();
}

} // namespace

DuckDnsUpdater::DuckDnsUpdater(boost::asio::io_context& ctx,
                               std::vector<std::string> domains,
                               std::string token,
                               int interval_seconds)
    : ctx_(ctx),
      domains_(std::move(domains)),
      token_(std::move(token)),
      interval_seconds_(std::max(interval_seconds, 60)),
      timer_(ctx) {}

void DuckDnsUpdater::start() {
    if (running_ || domains_.empty() || token_.empty()) return;
    running_ = true;
    launch_update();
}

void DuckDnsUpdater::stop() {
    running_ = false;
    timer_.cancel();
}

void DuckDnsUpdater::schedule_next() {
    if (!running_) return;
    timer_.expires_after(std::chrono::seconds(interval_seconds_));
    timer_.async_wait([this](const beast::error_code& ec) {
        if (ec || !running_) return;
        launch_update();
    });
}

void DuckDnsUpdater::launch_update() {
    auto domains = domains_;
    auto token = token_;
    std::thread([this, domains = std::move(domains), token = std::move(token)]() {
        try {
            auto response = perform_duckdns_update(domains, token);
            log_info("duckdns", "update ok domains=" + join_domains(domains) +
                                " response=" + response);
        } catch (const std::exception& ex) {
            log_warn("duckdns", std::string("update failed: ") + ex.what());
        }
        boost::asio::post(ctx_, [this]() { schedule_next(); });
    }).detach();
}

} // namespace cryptex
