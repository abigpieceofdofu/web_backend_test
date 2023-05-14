#include "http_handler.h"
#include "database.h"

// 实现请求处理器的 handleRequest 方法
void MyRequestHandler::handleRequest(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& resp)
{
    // 根据请求的路径或其他标识，执行相应的逻辑来处理请求
    if (req.getURI() == "/path1")
    {
        handleRegistrationRequest(req, resp);
        return;
    }
    else if (req.getURI() == "/path2")
    {
        // 处理 path2 请求的逻辑
        // ...
    }
    // 其他请求的处理逻辑
    // ...
}

// 实现请求处理器工厂的 createRequestHandler 方法
Poco::Net::HTTPRequestHandler* MyRequestHandlerFactory::createRequestHandler(const Poco::Net::HTTPServerRequest& request)
{
    // 创建并返回适当的请求处理器对象
    return new MyRequestHandler();
}

void MyRequestHandler::handleRegistrationRequest(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& resp)
{
    // 处理注册请求的逻辑
    // 从 req 中获取请求参数
    std::string username = req.get("username");
    std::string password = req.get("password");
    std::string email = req.get("email");
    std::string phoneNumber = req.get("phoneNumber");
    std::string address = req.get("address");

    try
    {
        // 获取数据库实例
        Database& db = Database::getInstance();

        // 调用数据库的 addUser 函数进行用户添加
        bool success = db.addUser(username, password, email, phoneNumber, address);

        if (success)
        {
            // 注册成功的处理逻辑
            resp.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
            resp.send();
        }
        else
        {
            // 注册失败的处理逻辑
            resp.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
            resp.send();
        }
    }
    catch (const std::exception& e)
    {
        // 处理异常情况
        resp.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
        resp.send();
    }
}
