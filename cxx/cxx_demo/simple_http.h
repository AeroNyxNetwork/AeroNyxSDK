#ifndef __SIMPLE_HTTP__H__
#define __SIMPLE_HTTP__H__
#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/beast/http/string_body.hpp>

std::string HttpGet(const std::string& host, const std::string& port, const std::string& target) {
    std::string rtn = "";
    try {
        boost::asio::io_context ioc;
        boost::asio::ip::tcp::resolver resolver(ioc);
        boost::asio::ip::tcp::socket socket(ioc);

        auto const results = resolver.resolve(host, port);

        boost::asio::connect(socket, results.begin(), results.end());
        boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::get, target, 11};
        req.set(boost::beast::http::field::host, host);
        req.set(boost::beast::http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        boost::beast::http::write(socket, req);
        boost::beast::flat_buffer buffer;
        boost::beast::http::response<boost::beast::http::dynamic_body> res;
        boost::beast::http::read(socket, buffer, res);

        std::string body = boost::beast::buffers_to_string(res.body().data());

        rtn = body;

        boost::beast::error_code ec;
        socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    } catch (std::exception const& e) {
        std::cout << "Faild:" << e.what() << std::endl;
    }
    return rtn;
}

#endif