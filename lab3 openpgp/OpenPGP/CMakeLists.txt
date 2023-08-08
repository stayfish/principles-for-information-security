cmake_minimum_required(VERSION 3.0.0)
project(OpenPGP VERSION 0.1.0)

include(CTest)
enable_testing()

set(CMAKE_C_FLAGS "${CMAKE_CFLAGS} -std=c++11 -w")
add_compile_options(-w)



# set(LIB ./lib/WinNTL-11_5_1)
# add_subdirectory(${LIB})
set(LIB ./lib/share/ntl)
link_directories(${LIB})
include_directories(./include ${LIB}/include)
# find_library(NTL ntl
#     PATHS ${LIB}
#     REQUIRED
# )
# if(NTL)
#     message("ntl Found: ${NTL}")
# else()
#     message(WARNING "ntl not found")
# endif()

aux_source_directory(./src SRC)
add_executable(${PROJECT_NAME} ${SRC})

target_link_libraries(${PROJECT_NAME} ntl)
# target_link_libraries(${PROJECT_NAME} ${NTL})


set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
