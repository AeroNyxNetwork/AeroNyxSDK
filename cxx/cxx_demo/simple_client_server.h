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

class SimpleClientServer{
public:
    SimpleClientServer(){}
    ~SimpleClientServer(){
        StopServer();
    }
public:
    bool StartServer(
        boost::asio::io_service& ios,
        bool auto_proxy,
        uint32_t port,
        const std::string& remote_ip,
        const uint16_t remote_port,
        const std::string& remote_pubkey,
        const std::string& token) {
            acceptor = std::make_shared<boost::asio::ip::tcp::acceptor>(ios, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port));
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
    bool StopServer() {
        if (acceptor) {
            try{
                acceptor->close();
                acceptor->cancel();
            }catch (...) {}
        }
        //    if (thread_func.joinable())
        //        try{thread_func.join();}catch(...){}
        while (acceptor_running == true) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        ClearClient();
        return true;
    }
private:
    std::thread thread_func;
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
                std::shared_ptr<SimpleClientItem> client = std::shared_ptr<SimpleClientItem>(new SimpleClientItem(ios, socket_in, auto_proxy, remote_ip, remote_port, remote_pubkey, token));
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
    void OnError(std::shared_ptr<SimpleClientItem> item) {
        RemoveClient(item);
    }
    void AddClient(std::shared_ptr<SimpleClientItem> client) {
        std::lock_guard<std::mutex> lk(socket_list_mutex);
        socket_list.insert(client);
        std::cout << (boost::format("add client: %d")%socket_list.size()).str() << std::endl;
    }
    size_t RemoveClient(std::shared_ptr<SimpleClientItem> client) {
        std::lock_guard<std::mutex> lk(socket_list_mutex);
        client->Clear();
        auto tmp = socket_list.erase(client);
        if (tmp)
            std::cout << (boost::format("remove client: %d")%socket_list.size()).str() << std::endl;
        return tmp;
    }
    void ClearClient() {
        std::lock_guard<std::mutex> lk(socket_list_mutex);
        for(auto item: socket_list) {
            item->Clear();
        }
        socket_list.clear();
    }
private:
    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor;
    bool acceptor_running = false;
    std::mutex socket_list_mutex;
    std::unordered_set<std::shared_ptr<SimpleClientItem>> socket_list;
    std::string remote_ip;
    uint16_t remote_port;

};

#endif