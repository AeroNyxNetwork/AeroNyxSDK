#ifndef __SIMPLE_CLIENT_ITEM__HPP__
#define __SIMPLE_CLIENT_ITEM__HPP__
#include <iostream>
#include <string>
#include <mutex>
#include <list>
#include <vector>
#include <atomic>

#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <boost/thread/lock_guard.hpp>
#include <boost/signals2.hpp>
#include <boost/beast.hpp>
#include <boost/algorithm/string.hpp>

#include "../crypto_tools/ecdh_manager/ecdh_manager.h"
#include "simple_package.h"
#include "simple_key.h"


class SimpleClientItem: public std::enable_shared_from_this<SimpleClientItem>
{
public:
    SimpleClientItem(boost::asio::io_service* ios, std::shared_ptr<boost::asio::ip::tcp::socket> socket, 
        bool auto_proxy,
        const std::string& remote_ip,
        const uint16_t remote_port,
        const std::string& remote_pubkey,
        const std::string& token):
        auto_proxy(auto_proxy), remote_ip(remote_ip), remote_port(remote_port), remote_pubkey(remote_pubkey), socket(socket), token(token){
        read_buf.resize(1024);
        websocket = std::shared_ptr<boost::beast::websocket::stream<boost::asio::ip::tcp::socket>>(
                new boost::beast::websocket::stream<boost::asio::ip::tcp::socket>(*ios));
    }

    ~SimpleClientItem(){
        Clear();
        std::cout << (boost::format("~client:%p")%this).str() << std::endl;
    }

    void Start(){
        socket_thread_func = std::thread(
                    std::bind(
                        &SimpleClientItem::SocketThreadFunc,
                        shared_from_this(), "/test", auto_proxy));
    }

    void SetOnErrorCallBack(std::function<void(std::shared_ptr<SimpleClientItem>)> cb){
        on_error = cb;
    }

    void SendErrorByThread(){
        std::thread(std::bind(&SimpleClientItem::SendError, shared_from_this())).detach();
    }

    void SendError(){
        if (on_error) {
            on_error(shared_from_this());
        }
    }

    void Clear(){
        std::lock_guard<std::mutex> lk(close_mutex);
        boost::system::error_code err;
        std::cout << (boost::format("enter clear: %p")%this).str() << std::endl;

        socket->close(err);
        socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both, err);
        websocket->next_layer().close(err);
        websocket->next_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, err);



        if (socket_thread_func.joinable()) {
            try{socket_thread_func.join();}catch(...){}
            socket_thread_func = std::thread();
        }

        if (websocket_thread_func.joinable()) {
            try{websocket_thread_func.join();}catch(...){}
            websocket_thread_func = std::thread();
        }
        std::cout << (boost::format("leave clear: %p")%this).str() << std::endl;
    }
private:
    // auto_proxy is for PAC
    void SocketThreadFunc(const std::string &path, bool auto_proxy) {
        try{
            // connect to websocket server of node
            boost::asio::ip::tcp::endpoint end_point;
            end_point = {boost::asio::ip::make_address(remote_ip), remote_port};
            is_pac = false;

            boost::system::error_code ec_tmp;
            websocket->next_layer().connect(end_point, ec_tmp);
            std::string host = end_point.address().to_string() + (boost::format(":%d")%end_point.port()).str();
            try{
                websocket->set_option(boost::beast::websocket::stream_base::decorator([](boost::beast::websocket::request_type&req){
                    req.set(boost::beast::http::field::user_agent, std::string(BOOST_BEAST_VERSION_STRING)+" websocket-client-coro");
            }));
            }catch(...){
            }

            websocket->handshake(host, path);
            websocket->binary(true);
            websocket_thread_func = std::thread(std::bind(&SimpleClientItem::WebSocketThreadFunc, shared_from_this()));


            // Read from local and send to remote
            while(true) {
                uint32_t size = socket->read_some(boost::asio::buffer(read_buf, read_buf.size()));
                WebSocketWrite(std::string(read_buf.data(), size));
            }
        }catch(...) {
            SendErrorByThread();
        }
    }
    void WebSocketThreadFunc() {
        try{
            while(true) {
                boost::beast::flat_buffer buffer;
                uint32_t size = websocket->read(buffer);
                std::string encode_buf = std::string((char*)boost::asio::buffer(buffer.data()).data(), size);
                DecodedWebsocketPackage decoded;

                bool res = DecodePackage( encode_buf, decoded, GetEcdhKey());
                if (res == false) {
                    throw "decode faild";
                }
                boost::asio::write(*socket, boost::asio::buffer(decoded.payload));
            }
        }catch(const boost::system::system_error& err){
            SendErrorByThread();
        }
        catch(...){
            SendErrorByThread();
        }
    }
    void SocketWrite(const std::string& buf){
        boost::asio::write(*socket, boost::asio::buffer(buf));
    }
    void WebSocketWrite(const std::string& buf){
        std::string encoded;
        bool x = websocket->binary();
        std::string sended_buf = token+buf;

        encoded = EncodePackage(GetStorePublicKey(), sended_buf, GetEcdhKey());
        
        websocket->write(boost::asio::buffer(encoded, encoded.size()));
    }
    std::string GetEcdhKey(){
        std::string ecdh_key = GetEcdhManager()->GetEcdh(std::make_pair(remote_pubkey, GetStorePrivateKey()));
        return ecdh_key;
    }
private:
    bool auto_proxy;
    std::string remote_ip;
    uint16_t remote_port;
    std::string remote_pubkey;
    bool is_pac = false;
    std::shared_ptr<boost::asio::ip::tcp::socket> socket;
    std::shared_ptr<boost::beast::websocket::stream<boost::asio::ip::tcp::socket>> websocket;
    std::thread socket_thread_func;
    std::thread websocket_thread_func;
    std::string read_buf;
    std::string readed;
    std::function<void(std::shared_ptr<SimpleClientItem>)> on_error;

    std::mutex close_mutex;
    std::string ecdh_key;
    std::string token;
};

#endif