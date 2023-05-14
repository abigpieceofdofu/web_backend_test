#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/ServerSocket.h>
#include <Poco/Net/HTTPServerParams.h>
#include "http_handler.h"
#include "database.h"

int main()
{
    Database& db = Database::getInstance();

    bool databaseExists = db.databaseExists();

    if (!databaseExists) {
        MYSQL* connection = db.getConnection();
        db.initializeDatabase(connection);
        db.releaseConnection(connection);
    }

    Poco::Net::SocketAddress address("127.0.0.1", 8888); // 设置IP地址和端口号
    Poco::Net::ServerSocket serverSocket(address);
    Poco::Net::HTTPServer server(new MyRequestHandlerFactory, Poco::Net::ServerSocket(8080), new Poco::Net::HTTPServerParams);
    server.start();
    getchar();
    server.stop();

    return 0;
}
