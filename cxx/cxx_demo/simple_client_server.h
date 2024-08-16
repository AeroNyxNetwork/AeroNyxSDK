#ifndef __SIMPLE_CLIENT_SERVER__H__
#define __SIMPLE_CLIENT_SERVER__H__

#include <boost/asio.hpp>
#include <boost/signals2.hpp>
#include <memory>
#include <list>
#include <unordered_set>
#include <mutex>
#include <thread>
#include "simple_client_item.h"

// Class that manages the server-side operations for handling client connections
class SimpleClientServer {
public:
    SimpleClientServer() {}
    ~SimpleClientServer() {
        StopServer();  // Ensure the server is stopped properly on destruction
    }

public:
    // Starts the server on a specified port and sets up client connection acceptance
    bool StartServer(
        boost::asio::io_service& ios,
        bool auto_proxy,
        uint32_t port,
        const std::string& remote_ip,
        const uint16_t remote_port,
        const std::string& remote_pubkey,
        const std::string& token) {
            acceptor = std::make_shared<boost::asio::ip::tcp::acceptor>(
                ios, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port));
            std::cout << "client_server is listening..." << std::endl;
            acceptor_running = true;
            std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::make_shared<boost::asio::ip::tcp::socket>(ios);
            acceptor->async_accept(*socket, std::bind(
                &SimpleClientServer::OnAccept,
                this,
                socket,
                &ios,
                auto_proxy,
                port,
                remote_ip,
                remote_port,
                remote_pubkey,
                token,
                std::placeholders::_1));
            return true;
        }

    // Stops the server and cleans up any active client connections
    bool StopServer() {
        if (acceptor) {
            try {
                acceptor->close();
                acceptor->cancel();
            } catch (...) {}
        }
        while (acceptor_running == true) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        ClearClient();
        return true;
    }

private:
    // Handles new client connections from the acceptor
    void OnAccept(
        std::shared_ptr<boost::asio::ip::tcp::socket> socket_in,
        boost::asio::io_service* ios,
        bool auto_proxy,
        uint32_t port,
        const std::string& remote_ip,
        const uint16_t remote_port,
        const std::string& remote_pubkey,
        const std::string& token, const boost::system::error_code& ec) {
            if (!ec) {
                std::shared_ptr<SimpleClientItem> client = std::make_shared<SimpleClientItem>(
                    ios, socket_in, auto_proxy, remote_ip, remote_port, remote_pubkey, token);
                client->SetOnErrorCallBack(std::bind(&SimpleClientServer::OnError, this, std::placeholders::_1));
                client->Start();
                AddClient(client);
                std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::make_shared<boost::asio::ip::tcp::socket>(*ios);
                acceptor->async_accept(*socket, std::bind(
                    &SimpleClientServer::OnAccept,
                    this,
                    socket,
                    ios,
                    auto_proxy,
                    port,
                    remote_ip,
                    remote_port,
                    remote_pubkey,
                    token,
                    std::placeholders::_1));
            } else {
                acceptor_running = false;
                std::cout << "Accept Error" << std::endl;
            }
        }

    // Error handling for clients
    void OnError(std::shared_ptr<SimpleClientItem> item) {
        RemoveClient(item);
    }

    // Adds a client to the internal list for management
    void AddClient(std::shared_ptr<SimpleClientItem> client) {
        std::lock_guard<std::mutex> lk(socket_list_mutex);
        socket_list.insert(client);
        std::cout << (boost::format("add client: %d") % socket_list.size()).str() << std::endl;
    }

    // Removes a client from the list and cleans up resources
    size_t RemoveClient(std::shared_ptr<SimpleClientItem> client) {
        std::lock_guard<std::mutex> lk(socket_list_mutex);
        client->Clear();
        auto tmp = socket_list.erase(client);
        if (tmp)
            std::cout << (boost::format("remove client: %d") % socket_list.size()).str() << std::endl;
        return tmp;
    }

    // Clears all clients from the list
    void ClearClient() {
        std::lock_guard<std::mutex> lk(socket_list_mutex);
        for (auto item : socket_list) {
            item->Clear();
        }
        socket_list.clear();
    }

private:
    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor;  // TCP acceptor for incoming connections
    bool acceptor_running = false;  // Indicates if the acceptor is still running
    std::mutex socket_list_mutex;  // Mutex to protect the list of clients
    std::unordered_set<std::shared_ptr<SimpleClientItem>> socket_list;  // Set of active clients
    std::string remote_ip;  // Remote IP for the server
    uint16_t remote_port;  // Remote port for the server

};

#endif // __SIMPLE_CLIENT_SERVER__H__
