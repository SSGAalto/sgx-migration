/*
 * TcpServer.h
 *
 *  Created on: Aug 22, 2017
 */

#ifndef NETWORK_NETWORK_COMMON_H_
#define NETWORK_NETWORK_COMMON_H_

#include "network_types.h"
#include "TcpConnection.h"

#include <iostream>
#include <string>
#include <functional>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>

using boost::asio::ip::tcp;

namespace network{
    class TcpServer
    {
        public:
        /**
        * @brief Consructs an new TcpServer
        * @param io_service designated io_service
        * @param port the TCP port to use for listening
        * @param handler callback function for received messages
        */
            TcpServer(boost::asio::io_service& io_service, unsigned short port,
                    std::function<int(TcpConnection *conn, message_t *msg)> callback);
            ~TcpServer(){};

        private:
            tcp::acceptor acceptor_;
            std::function<int(TcpConnection *conn, message_t *msg)> callback;

            /**
            * Start accepting new connections
            */
            void start_accept();

            /**
            * handle new connections
            */
            void handle_accept(TcpConnection::ptr new_connection, const boost::system::error_code& error);
    };

}
#endif /* NETWORK_NETWORK_COMMON_H_ */
