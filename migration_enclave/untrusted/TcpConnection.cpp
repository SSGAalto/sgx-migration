/*
 * TcpConnection.cpp
 *
 *  Created on: Aug 22, 2017
 */

#include "TcpConnection.h"

namespace network{

    TcpConnection::ptr TcpConnection::create(boost::asio::io_service& io_service) {
        return ptr(new TcpConnection(io_service));
    }

    tcp::socket& TcpConnection::socket() {
        return socket_;
    }

    std::string TcpConnection::to_string() {
        boost::asio::ip::tcp::endpoint endpoint = socket_.remote_endpoint();
        std::string res = endpoint.address().to_string();
        res = res + ":" + boost::lexical_cast<std::string>(endpoint.port());
        return res;
    }

    boost::system::error_code TcpConnection::send_message(message_t *msg){
        boost::system::error_code error;
        boost::array<uint32_t, MESSAGE_HEADER_SIZE> out_buf = {msg->size_encrypted, msg->size_plaintext, msg->type, msg->session_id};
        int len = boost::asio::write(socket_, boost::asio::buffer(out_buf), boost::asio::transfer_all() , error);
        if(error.value() != boost::system::errc::success){
            return error;
        }
        //std::cout << "Sent " << std::dec << len << " bytes:" << out_buf[0] << " " << std::hex << out_buf[1] << " " << out_buf[2]<< std::endl;

        //only send buffer if we want to and data is not null
        if(msg->size_encrypted > 0 && msg->data_encrypted){
            int len = boost::asio::write(socket_, boost::asio::buffer(msg->data_encrypted, msg->size_encrypted), boost::asio::transfer_all(), error);
            //std::cout << "And additionally sent " << len << " bytes as data." << std::endl;
        }

        if(error.value() != boost::system::errc::success){
          return error;
        }

        //only send buffer if we want to and data is not null
        if(msg->size_plaintext > 0 && msg->data_plaintext){
            int len = boost::asio::write(socket_, boost::asio::buffer(msg->data_plaintext, msg->size_plaintext), boost::asio::transfer_all(), error);
            //std::cout << "And additionally sent " << len << " bytes as data." << std::endl;
        }

        return error;
    }

    void TcpConnection::receive_msg(std::function<void(TcpConnection *conn, message_t *msg)> callback) {
        auto self(shared_from_this());
        boost::array<uint32_t, MESSAGE_HEADER_SIZE> buf;


        boost::asio::async_read(socket_,
            //boost::asio::buffer(buf),
            boost::asio::buffer(header),
            [this, self, callback](boost::system::error_code error, size_t size)
        {

            if(error){
                if(error == boost::asio::error::eof) {
                    return; //no payload, close this connection
                }

                std::cout << "TcpConnection::receiveMsg error at receive header: " <<
                error << " (size: " << size << ")" << std::endl;
                return;
            }

            message_t msg;
            msg.size_encrypted = header[0];
            msg.size_plaintext = header[1];
            msg.type = header[2];
            msg.session_id = header[3];
            msg.data_encrypted = NULL;
            msg.data_plaintext = NULL;

            //std::cout << "Received " << size << " bytes. message enc size " << msg.size_encrypted << " and size plaintext " << msg.size_plaintext << " and type " << msg.type << std::endl;

            //printf("enc:%x, plain:%x, type:%x, id:%x\n", msg.size_encrypted, msg.size_plaintext, msg.type, msg.session_id);

            size_t len;
            if(msg.size_encrypted > 0){
                //Read data
                void *read_encrypted = malloc(msg.size_encrypted);
                msg.data_encrypted = read_encrypted;
                len = boost::asio::read(socket_, boost::asio::buffer(msg.data_encrypted, msg.size_encrypted), error);
                //std::cout << "And additionally read " << len << " bytes as data." << std::endl;

                if(error.value() != boost::system::errc::success){
                    std::cout << "TcpConnection::receiveMsg error at receive encrypted data: " <<
                    error << " (size: " << len << ")" << std::endl;
                    return;
                }
            }


            if(msg.size_plaintext > 0){
                //Read data
                void *read_plaintext = malloc(msg.size_plaintext);
                msg.data_plaintext = read_plaintext;
                len = boost::asio::read(socket_, boost::asio::buffer(msg.data_plaintext, msg.size_plaintext), error);
                //std::cout << "And additionally read " << len << " bytes as data." << std::endl;

                if(error.value() != boost::system::errc::success){
                    std::cout << "TcpConnection::receiveMsg error at receive plaintext data: " <<
                    error << " (size: " << len << ")" << std::endl;
                    return;
                }
            }


            callback(this, &msg);

            if(msg.data_encrypted != NULL) free(msg.data_encrypted);
            if(msg.data_plaintext != NULL) free(msg.data_plaintext);

            receive_msg(callback);
        });
    }

}
