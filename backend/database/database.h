#ifndef DATABASE_H
#define DATABASE_H

#include <mutex>
#include <memory>
#include <mysql.h>
#include <iostream>
#include <string>

class Database {
public:
    // 获取数据库实例（单例模式）
    static Database& getInstance();

    // 删除拷贝构造函数和赋值运算符
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    // 获取一个数据库连接
    MYSQL* getConnection();

    // 释放数据库连接
    void releaseConnection(MYSQL* connection);

    // 测试数据库连接
    bool testConnection();

    bool databaseExists();

    void initializeDatabase(MYSQL* conn);

    // 用户相关操作
    bool addUser(const std::string& username, const std::string& password, const std::string& email, const std::string& phoneNumber = "", const std::string& address = "");
    bool deleteUser(int userId);
    bool updateUser(int userId, const std::string& username, const std::string& password, const std::string& email, const std::string& phoneNumber = "", const std::string& address = "");
    MYSQL_ROW getUser(int userId);

    // 商品相关操作
    bool addProduct(const std::string& productName, const std::string& description, double originalPrice, double discountedPrice, double commission, int stockQuantity, int categoryID, const std::string& imageURL, const std::string& originalURL);
    bool deleteProduct(int productId);
    bool updateProduct(int productId, const std::string& productName, const std::string& description, double originalPrice, double discountedPrice, double commission, int stockQuantity, int categoryID, const std::string& imageURL, const std::string& originalURL);
    MYSQL_ROW getProduct(int productId);

    // 订单相关操作
    bool addOrder(int userId, const std::string& orderDate, const std::string& shipmentDate, const std::string& shippingAddress, double totalPrice);
    bool deleteOrder(int orderId);
    bool updateOrder(int orderId, int userId, const std::string& orderDate, const std::string& shipmentDate, const std::string& shippingAddress, double totalPrice);
    MYSQL_ROW getOrder(int orderId);

private:
    // 私有构造函数（单例模式）
    Database();

    // 私有析构函数
    ~Database();

    // 数据库连接信息
    std::string host;
    unsigned int port;
    std::string user;
    std::string password;
    std::string dbName;

    // 连接池设置
    int maxConnections;
    int idleConnections;
    int activeConnections;

    // 用于保护连接池的互斥锁
    std::mutex connectionMutex;
};

class DatabaseConnectionException : public std::exception {
public:
    const char* what() const noexcept override {
        return "Database connection error.";
    }
};

class InsertionException : public std::exception {
public:
    const char* what() const noexcept override {
        return "Failed to insert data into the database.";
    }
};

class InvalidInputException : public std::exception {
public:
    const char* what() const noexcept override {
        return "Invalid input data.";
    }
};

class DeletionException : public std::exception {
public:
    const char* what() const noexcept override {
        return "Failed to delete data from the database.";
    }
};

class UpdateException : public std::exception {
public:
    const char* what() const noexcept override {
        return "Failed to update data in the database.";
    }
};

class QueryException : public std::exception {
public:
    const char* what() const noexcept override {
        return "Failed to execute database query.";
    }
};

std::string generateSalt();
std::string hashPassword(const std::string& password, const std::string& salt);
#endif // DATABASE_H
