/*
 * TcpConnection.h
 *
 *  Created on: Aug 22, 2017
 */

#ifndef ENCLAVE_MIGRATION_ENCLAVE_UNTRUSTED_TCPCONNECTION_H_
#define ENCLAVE_MIGRATION_ENCLAVE_UNTRUSTED_TCPCONNECTION_H_

#include "network_types.h"

#include <iostream>
#include <string>
#include <functional>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/lexical_cast.hpp>

using boost::asio::ip::tcp;

namespace network{
    class TcpConnection :
        public boost::enable_shared_from_this<TcpConnection>
        {
            public:
                typedef boost::shared_ptr<TcpConnection> ptr;
                TcpConnection(boost::asio::io_service& io_service) : socket_(io_service) {};
                ~TcpConnection(){};

                /**
                * Create a shared pointer to a new TcpConnection and return it
                */
                static ptr create(boost::asio::io_service& ios);

                /**
                * Obtain a reference to the socket belonging to this connection
                */
                tcp::socket& socket();

                /**
                * @brief Asynchronously write an earlier prepared message to the connection.
                *  This is used in the handle message (callback of receive) to send a response to a request.
                *  @param msg The message
                */
                boost::system::error_code send_message(message_t *msg);

                /**
                * @brief Wait for a message, receive it, and call callback with the received data
                * @param callback function
                */
                void receive_msg(std::function<void(TcpConnection *conn, message_t *msg)> callback);

                /**
                * @brief String representation of a remote endpoint, same as remote_enclave to string
                */
                std::string to_string();

            private:
                tcp::socket socket_;
                std::string message_;
                uint32_t header[MESSAGE_HEADER_SIZE];

                void handle_write(const boost::system::error_code& error, size_t data_size) {};

        };
} // network

#endif /* ENCLAVE_MIGRATION_ENCLAVE_UNTRUSTED_TCPCONNECTION_H_ */
