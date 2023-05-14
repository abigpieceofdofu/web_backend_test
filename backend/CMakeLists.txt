# CMakeList.txt: backend 的 CMake 项目，在此处包括源代码并定义
# 项目特定的逻辑。
#

link_directories("E:\\libraries\\mysql\\lib")
link_directories("E:\\libraries\\poco-poco-1.11.6\\build-debug64\\lib\\Debug")
link_directories("E:\\libraries\\OpenSSL-Win64\\lib")

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}/database
	${CMAKE_CURRENT_SOURCE_DIR}/http
	"E:\\libraries\\mysql\\include"
	"E:\\libraries\\poco-poco-1.11.6\\Net\\include"
	"E:\\libraries\\poco-poco-1.11.6\\Foundation\\include"
	"E:\\libraries\\OpenSSL-Win64\\include"
)

# 设置需要的源文件列表
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/http/http_handler.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/database/database.cpp
)

# 添加可执行文件和源文件
add_executable(main ${SOURCES} )

# 链接MySQL Connector/C++库到项目
target_link_libraries(main libmysql)
target_link_libraries(main PocoFoundationd PocoNetd)
target_link_libraries(main libssl libcrypto)

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET main PROPERTY CXX_STANDARD 20)
endif()

# TODO: 如有需要，请添加测试并安装目标。
