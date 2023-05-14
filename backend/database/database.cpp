#include "database.h"
#include <iostream>
#include <vector>
#include <stdexcept>
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/rand.h>


// 获取数据库实例（单例模式）
Database& Database::getInstance() {
    static Database instance;
    return instance;
}

// 私有构造函数（单例模式）
Database::Database() {
    host = "localhost";
    port = 3306;
    user = "root";
    password = "3.1415926535";
    dbName = "ECommerce";
    maxConnections = 10;
    idleConnections = 5;
    activeConnections = 0;
}

// 私有析构函数
Database::~Database() {
    // 关闭所有连接
}

// 获取一个数据库连接
MYSQL* Database::getConnection() {
    std::lock_guard<std::mutex> lock(connectionMutex);

    MYSQL* connection = mysql_init(nullptr);
    if (!mysql_real_connect(connection, host.c_str(), user.c_str(), password.c_str(), dbName.c_str(), port, nullptr, 0)) {
        std::cerr << "连接失败: " << mysql_error(connection) << std::endl;
        mysql_close(connection);
        return nullptr;
    }
    return connection;
}

// 释放数据库连接
void Database::releaseConnection(MYSQL* connection) {
    if (connection) {
        mysql_close(connection);
    }
}

bool Database::testConnection() {
    MYSQL* connection = getConnection();
    if (connection) {
        releaseConnection(connection);
        return true;
    }
    return false;
}

bool Database::databaseExists() {
    MYSQL* connection = getConnection();

    // 检查数据库是否存在的 SQL 查询语句
    const std::string query = "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = 'ECommerce'";

    int result = mysql_query(connection, query.c_str());
    if (result != 0) {
        // 查询执行出错
        releaseConnection(connection);
        throw QueryException();
    }

    MYSQL_RES* resultSet = mysql_store_result(connection);
    bool exists = mysql_num_rows(resultSet) > 0;

    mysql_free_result(resultSet);
    releaseConnection(connection);

    return exists;
}


void Database::initializeDatabase(MYSQL* conn)
{
    // List all your initialization SQL commands
    std::vector<const char*> commands =
    {
        "CREATE DATABASE IF NOT EXISTS ECommerce;",

        "USE ECommerce;",

        "CREATE TABLE IF NOT EXISTS Users ("
        "UserID INT AUTO_INCREMENT PRIMARY KEY,"
        "Username VARCHAR(255) NOT NULL,"
        "Password VARCHAR(255) NOT NULL,"
        "salt VARCHAR(255) NOT NULL,"
        "Email VARCHAR(255) UNIQUE,"
        "PhoneNumber VARCHAR(20),"
        "Address VARCHAR(255),"
        "RegistrationDate DATETIME,"
        "LastLogin DATETIME,"
        "Role ENUM('Admin', 'User') DEFAULT 'User'"
        ");",

        "CREATE TABLE IF NOT EXISTS ProductCategories ("
        "CategoryID INT AUTO_INCREMENT PRIMARY KEY,"
        "CategoryName VARCHAR(255) NOT NULL,"
        "Description TEXT"
        ");",

        "CREATE TABLE IF NOT EXISTS Products ("
        "ProductID INT AUTO_INCREMENT PRIMARY KEY,"
        "ProductName VARCHAR(255) NOT NULL,"
        "Description TEXT,"
        "OriginalPrice DECIMAL(10, 2) NOT NULL,"
        "DiscountedPrice DECIMAL(10, 2) NOT NULL,"
        "Commission DECIMAL(10, 2) NOT NULL,"
        "StockQuantity INT NOT NULL,"
        "CategoryID INT,"
        "ImageURL VARCHAR(255),"
        "OriginalURL VARCHAR(255) NOT NULL,"
        "AddDate DATETIME,"
        "UpdateDate DATETIME,"
        "FOREIGN KEY (CategoryID) REFERENCES ProductCategories(CategoryID)"
        ");",

        "CREATE TABLE IF NOT EXISTS Orders ("
        "OrderID INT AUTO_INCREMENT PRIMARY KEY,"
        "UserID INT,"
        "OrderDate DATETIME,"
        "ShipmentDate DATETIME,"
        "ShippingAddress VARCHAR(255),"
        "TotalPrice DECIMAL(10, 2),"
        "OrderStatus ENUM('Ordered', 'Paid', 'Shipped', 'Completed') DEFAULT 'Ordered',"
        "FOREIGN KEY (UserID) REFERENCES Users(UserID)"
        ");",

        "CREATE TABLE IF NOT EXISTS OrderDetails ("
        "OrderDetailID INT AUTO_INCREMENT PRIMARY KEY,"
        "OrderID INT,"
        "ProductID INT,"
        "Quantity INT,"
        "Price DECIMAL(10, 2),"
        "FOREIGN KEY (OrderID) REFERENCES Orders(OrderID),"
        "FOREIGN KEY (ProductID) REFERENCES Products(ProductID)"
        ");"
    };

    for (const auto& command : commands)
    {
        if (mysql_query(conn, command)) {
            std::cout << "Query error: " << mysql_error(conn) << std::endl;
            throw std::runtime_error(mysql_error(conn));
        }
    }
}

// 用户相关操作
bool Database::addUser(const std::string& userName, const std::string& password, const std::string& email, const std::string& phoneNumber, const std::string& address) {
    if (userName.empty() || password.empty() || email.empty()) {
        throw InvalidInputException();
    }

    MYSQL* connection = getConnection();
    if (!connection) {
        std::cerr << "Failed to get database connection." << std::endl;
        throw DatabaseConnectionException();
        return false;
    }
    // 哈希+盐
    std::string salt = generateSalt();
    std::string hashedPassword = hashPassword(password, salt);

    std::string query = "INSERT INTO Users (UserName, Password, Email, PhoneNumber, Address, RegistrationDate, LastLogin) VALUES ('"
        + userName + "', '"
        + hashedPassword + "', '"
        + salt + "', '"
        + email + "', '"
        + (phoneNumber.empty() ? "NULL" : phoneNumber) + "', '"
        + (address.empty() ? "NULL" : address) + "', "
        + "NOW(), NOW())";

    if (mysql_query(connection, query.c_str())) {
        std::cerr << "Insertion failed: " << mysql_error(connection) << std::endl;
        throw InsertionException();
        releaseConnection(connection);
        return false;
    }

    std::cout << "Insertion succeeded: Username=" << userName << ", Email=" << email << std::endl;
    releaseConnection(connection);
    return true;
}

bool Database::deleteUser(int userId) {
    MYSQL* connection = getConnection();
    if (!connection) {
        std::cerr << "Failed to get database connection." << std::endl;
        return false;
    }

    std::string query = "DELETE FROM Users WHERE UserID = " + std::to_string(userId);
    if (mysql_query(connection, query.c_str())) {
        std::cerr << "Deletion failed: " << mysql_error(connection) << std::endl;
        releaseConnection(connection);
        return false;
    }

    std::cout << "Deletion succeeded: UserID=" << userId << std::endl;
    releaseConnection(connection);
    return true;
}

bool Database::updateUser(int userId, const std::string& username, const std::string& password, const std::string& email, const std::string& phoneNumber, const std::string& address) {
    MYSQL* connection = getConnection();
    if (!connection) {
        std::cerr << "Failed to get database connection." << std::endl;
        return false;
    }

    std::string query = "UPDATE Users SET "
        "UserName = '" + username + "', "
        "Password = '" + password + "', "
        "Email = '" + email + "', "
        "PhoneNumber = '" + phoneNumber + "', "
        "Address = '" + address + "' "
        "WHERE UserID = " + std::to_string(userId);

    if (mysql_query(connection, query.c_str())) {
        std::cerr << "Update failed: " << mysql_error(connection) << std::endl;
        releaseConnection(connection);
        return false;
    }

    std::cout << "Update succeeded: UserID=" << userId << std::endl;
    releaseConnection(connection);
    return true;
}

MYSQL_ROW Database::getUser(int userId) {
    if (userId <= 0) {
        throw InvalidInputException();
    }

    MYSQL* connection = getConnection();
    if (!connection) {
        std::cerr << "Failed to get database connection." << std::endl;
        throw DatabaseConnectionException();
        return nullptr;
    }

    std::string query = "SELECT * FROM Users WHERE UserID = " + std::to_string(userId);
    if (mysql_query(connection, query.c_str())) {
        std::cerr << "Query failed: " << mysql_error(connection) << std::endl;
        throw QueryException();
        releaseConnection(connection);
        return nullptr;
    }

    MYSQL_RES* result = mysql_store_result(connection);
    MYSQL_ROW row = mysql_fetch_row(result);

    releaseConnection(connection);
    return row;
}

// 商品相关操作
bool Database::addProduct(const std::string& productName, const std::string& description, double originalPrice, double discountedPrice, double commission, int stockQuantity, int categoryID, const std::string& imageURL, const std::string& originalURL) {
    if (productName.empty() || description.empty()) {
        throw InvalidInputException();
    }

    MYSQL* connection = getConnection();
    if (!connection) {
        std::cerr << "Failed to get database connection." << std::endl;
        throw DatabaseConnectionException();
        return false;
    }

    std::string query = "INSERT INTO Products (ProductName, Description, OriginalPrice, DiscountedPrice, Commission, StockQuantity, CategoryID, ImageURL, OriginalURL) VALUES ('"
        + productName + "', '"
        + description + "', "
        + std::to_string(originalPrice) + ", "
        + std::to_string(discountedPrice) + ", "
        + std::to_string(commission) + ", "
        + std::to_string(stockQuantity) + ", "
        + std::to_string(categoryID) + ", '"
        + imageURL + "', '"
        + originalURL + "')";

    if (mysql_query(connection, query.c_str())) {
        std::cerr << "Insertion failed: " << mysql_error(connection) << std::endl;
        throw InsertionException();
        releaseConnection(connection);
        return false;
    }

    std::cout << "Insertion succeeded: ProductName=" << productName << std::endl;
    releaseConnection(connection);
    return true;
}

bool Database::deleteProduct(int productId) {
    MYSQL* connection = getConnection();
    if (!connection) {
        std::cerr << "Failed to get database connection." << std::endl;
        throw DatabaseConnectionException();
        return false;
    }

    std::string query = "DELETE FROM Products WHERE ProductID = " + std::to_string(productId);
    if (mysql_query(connection, query.c_str())) {
        std::cerr << "Deletion failed: " << mysql_error(connection) << std::endl;
        throw DeletionException();
        releaseConnection(connection);
        return false;
    }

    std::cout << "Deletion succeeded: ProductID=" << productId << std::endl;
    releaseConnection(connection);
    return true;
}

bool Database::updateProduct(int productId, const std::string& productName, const std::string& description, double originalPrice, double discountedPrice, double commission, int stockQuantity, int categoryID, const std::string& imageURL, const std::string& originalURL) {
    MYSQL* connection = getConnection();
    if (!connection) {
        std::cerr << "Failed to get database connection." << std::endl;
        throw DatabaseConnectionException();
        return false;
    }

    std::string query = "UPDATE Products SET "
        "ProductName = '" + productName + "', "
        "Description = '" + description + "', "
        "OriginalPrice = " + std::to_string(originalPrice) + ", "
        "DiscountedPrice = " + std::to_string(discountedPrice) + ", "
        "Commission = " + std::to_string(commission) + ", "
        "StockQuantity = " + std::to_string(stockQuantity) + ", "
        "CategoryID = " + std::to_string(categoryID) + ", "
        "ImageURL = '" + imageURL + "', "
        "OriginalURL = '" + originalURL + "' "
        "WHERE ProductID = " + std::to_string(productId);

    if (mysql_query(connection, query.c_str())) {
        std::cerr << "Update failed: " << mysql_error(connection) << std::endl;
        throw UpdateException();
        releaseConnection(connection);
        return false;
    }

    std::cout << "Update succeeded: ProductID=" << productId << std::endl;
    releaseConnection(connection);
    return true;
}

MYSQL_ROW Database::getProduct(int productId) {
    MYSQL* connection = getConnection();
    if (!connection) {
        std::cerr << "Failed to get database connection." << std::endl;
        throw DatabaseConnectionException();
        return nullptr;
    }

    std::string query = "SELECT * FROM Products WHERE ProductID = " + std::to_string(productId);
    if (mysql_query(connection, query.c_str())) {
        std::cerr << "Query failed: " << mysql_error(connection) << std::endl;
        throw QueryException();
        releaseConnection(connection);
        return nullptr;
    }

    MYSQL_RES* result = mysql_store_result(connection);
    MYSQL_ROW row = mysql_fetch_row(result);

    releaseConnection(connection);
    return row;
}



// 订单相关操作
bool Database::addOrder(int userId, const std::string& orderDate, const std::string& shipmentDate, const std::string& shippingAddress, double totalPrice) {
    if (userId <= 0) {
        throw InvalidInputException();
    }

    MYSQL* connection = getConnection();
    if (!connection) {
        std::cerr << "Failed to get database connection." << std::endl;
        throw DatabaseConnectionException();
        return false;
    }

    std::string query = "INSERT INTO Orders (UserID, OrderDate, ShipmentDate, ShippingAddress, TotalPrice) VALUES ("
        + std::to_string(userId) + ", '"
        + orderDate + "', '"
        + shipmentDate + "', '"
        + shippingAddress + "', "
        + std::to_string(totalPrice) + ")";

    if (mysql_query(connection, query.c_str())) {
        std::cerr << "Insertion failed: " << mysql_error(connection) << std::endl;
        throw InsertionException();
        releaseConnection(connection);
        return false;
    }

    std::cout << "Insertion succeeded: UserID=" << userId << ", OrderDate=" << orderDate << std::endl;
    releaseConnection(connection);
    return true;
}

bool Database::deleteOrder(int orderId) {
    MYSQL* connection = getConnection();
    if (!connection) {
        std::cerr << "Failed to get database connection." << std::endl;
        throw DatabaseConnectionException();
        return false;
    }

    std::string query = "DELETE FROM Orders WHERE OrderID = " + std::to_string(orderId);
    if (mysql_query(connection, query.c_str())) {
        std::cerr << "Deletion failed: " << mysql_error(connection) << std::endl;
        throw DeletionException();
        releaseConnection(connection);
        return false;
    }

    std::cout << "Deletion succeeded: OrderID=" << orderId << std::endl;
    releaseConnection(connection);
    return true;
}

bool Database::updateOrder(int orderId, int userId, const std::string& orderDate, const std::string& shipmentDate, const std::string& shippingAddress, double totalPrice) {
    if (orderId <= 0 || userId <= 0) {
        throw InvalidInputException();
    }

    MYSQL* connection = getConnection();
    if (!connection) {
        std::cerr << "Failed to get database connection." << std::endl;
        throw DatabaseConnectionException();
        return false;
    }

    std::string query = "UPDATE Orders SET "
        "UserID = " + std::to_string(userId) + ", "
        "OrderDate = '" + orderDate + "', "
        "ShipmentDate = '" + shipmentDate + "', "
        "ShippingAddress = '" + shippingAddress + "', "
        "TotalPrice = " + std::to_string(totalPrice) + " "
        "WHERE OrderID = " + std::to_string(orderId);

    if (mysql_query(connection, query.c_str())) {
        std::cerr << "Update failed: " << mysql_error(connection) << std::endl;
        throw UpdateException();
        releaseConnection(connection);
        return false;
    }

    std::cout << "Update succeeded: OrderID=" << orderId << std::endl;
    releaseConnection(connection);
    return true;
}

MYSQL_ROW Database::getOrder(int orderId) {
    if (orderId <= 0) {
        throw InvalidInputException();
    }

    MYSQL* connection = getConnection();
    if (!connection) {
        std::cerr << "Failed to get database connection." << std::endl;
        throw DatabaseConnectionException();
        return nullptr;
    }

    std::string query = "SELECT * FROM Orders WHERE OrderID = " + std::to_string(orderId);
    if (mysql_query(connection, query.c_str())) {
        std::cerr << "Query failed: " << mysql_error(connection) << std::endl;
        throw QueryException();
        releaseConnection(connection);
        return nullptr;
    }

    MYSQL_RES* result = mysql_store_result(connection);
    MYSQL_ROW row = mysql_fetch_row(result);

    releaseConnection(connection);
    return row;
}

std::string generateSalt() {
    const int saltSize = 16; // 盐值长度，根据需求调整
    unsigned char salt[saltSize];
    if (RAND_bytes(salt, saltSize) != 1) {
        throw std::runtime_error("Failed to generate salt");
    }
    std::string saltString(reinterpret_cast<char*>(salt), saltSize);
    return saltString;
}

std::string hashPassword(const std::string& password, const std::string& salt) {
    const EVP_MD* md = EVP_sha256();  // 选择哈希算法，这里使用 SHA-256

    // 创建哈希上下文
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        // 处理创建上下文失败的情况
        throw std::runtime_error("Failed to create hash context.");
    }

    // 初始化哈希上下文
    if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1) {
        // 处理初始化上下文失败的情况
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to initialize hash context.");
    }

    // 添加盐值到哈希上下文
    if (EVP_DigestUpdate(mdctx, salt.c_str(), salt.length()) != 1) {
        // 处理添加盐值失败的情况
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to add salt to hash context.");
    }

    // 添加密码到哈希上下文
    if (EVP_DigestUpdate(mdctx, password.c_str(), password.length()) != 1) {
        // 处理添加密码失败的情况
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to add password to hash context.");
    }

    // 计算哈希值
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLength;
    if (EVP_DigestFinal_ex(mdctx, hash, &hashLength) != 1) {
        // 处理计算哈希值失败的情况
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to calculate hash value.");
    }

    // 将哈希值转换为十六进制字符串
    std::stringstream hexStream;
    hexStream << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < hashLength; ++i) {
        hexStream << std::setw(2) << static_cast<unsigned int>(hash[i]);
    }

    // 释放哈希上下文
    EVP_MD_CTX_free(mdctx);

    // 返回哈希值的十六进制字符串表示
    return hexStream.str();
}
