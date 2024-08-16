#ifndef __SIMPLE_HTTP__H__
#define __SIMPLE_HTTP__H__

#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/beast/http/string_body.hpp>

// Function to perform an HTTP GET request
std::string HttpGet(const std::string& host, const std::string& port, const std::string& target) {
    std::string rtn = "";  // Variable to store the response body as a string
    try {
        boost::asio::io_context ioc;  // Context for managing objects requiring I/O
        boost::asio::ip::tcp::resolver resolver(ioc);  // Resolver to turn the server name into a TCP endpoint
        boost::asio::ip::tcp::socket socket(ioc);  // Socket for the connection

        // Resolve the host name and service to a list of endpoints
        auto const results = resolver.resolve(host, port);

        // Establish a connection to the first endpoint in the list of resolved endpoints
        boost::asio::connect(socket, results.begin(), results.end());

        // Create an HTTP GET request message
        boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::get, target, 11};
        req.set(boost::beast::http::field::host, host);  // Set the Host HTTP header
        req.set(boost::beast::http::field::user_agent, BOOST_BEAST_VERSION_STRING);  // Set the User-Agent HTTP header

        // Send the HTTP request to the remote host
        boost::beast::http::write(socket, req);

        // This buffer is used for reading and must be persisted
        boost::beast::flat_buffer buffer;  
        // Declare a container to hold the response
        boost::beast::http::response<boost::beast::http::dynamic_body> res;

        // Receive the HTTP response
        boost::beast::http::read(socket, buffer, res);

        // Convert the response body to a string
        std::string body = boost::beast::buffers_to_string(res.body().data());
        rtn = body;

        // Gracefully close the socket
        boost::beast::error_code ec;
        socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    } catch (std::exception const& e) {
        std::cout << "Failed: " << e.what() << std::endl;  // Output error message if an exception is thrown
    }
    return rtn;
}

#endif  // __SIMPLE_HTTP__H__
