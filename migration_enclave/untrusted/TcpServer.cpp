/*
 * TcpServer.cpp
 *
 *  Created on: Aug 22, 2017
 */


#include "TcpServer.h"

namespace network{


TcpServer::TcpServer(boost::asio::io_service& io_service, unsigned short port,
        std::function<int(TcpConnection *conn, message_t *msg)> callback)
            : acceptor_(io_service, tcp::endpoint(tcp::v4(), port)),
              callback(callback) {
    start_accept();
}


void TcpServer::start_accept() {
    TcpConnection::ptr new_connection = TcpConnection::create(acceptor_.get_io_service());

    acceptor_.async_accept(new_connection->socket(),
            boost::bind(&TcpServer::handle_accept, this, new_connection,
            boost::asio::placeholders::error));
}

void TcpServer::handle_accept(TcpConnection::ptr new_connection, const boost::system::error_code& error) {
    if (!error) {
        new_connection->receive_msg(callback);
    }

    start_accept();
}

} // namespace


