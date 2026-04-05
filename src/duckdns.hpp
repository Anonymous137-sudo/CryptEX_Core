#pragma once

#include <boost/asio.hpp>
#include <memory>
#include <string>
#include <vector>

namespace cryptex {

class DuckDnsUpdater {
public:
    DuckDnsUpdater(boost::asio::io_context& ctx,
                   std::vector<std::string> domains,
                   std::string token,
                   int interval_seconds);

    void start();
    void stop();

private:
    void schedule_next();
    void launch_update();

    boost::asio::io_context& ctx_;
    std::vector<std::string> domains_;
    std::string token_;
    int interval_seconds_{300};
    boost::asio::steady_timer timer_;
    bool running_{false};
};

} // namespace cryptex
