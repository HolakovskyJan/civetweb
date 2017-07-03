# The C API library
add_library(c-library civetweb.c)
set_target_properties(c-library PROPERTIES
  OUTPUT_NAME "civetweb"
  VERSION ${CIVETWEB_VERSION}
  SOVERSION ${CIVETWEB_VERSION}
)
if (BUILD_SHARED_LIBS)
  target_compile_definitions(c-library PRIVATE CIVETWEB_DLL_EXPORTS)
endif()
target_include_directories(
  c-library PUBLIC
  ${PROJECT_SOURCE_DIR}/include)
install(
  TARGETS c-library
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib
  RUNTIME DESTINATION bin
  COMPONENT c-library)
install(FILES
  ${PROJECT_SOURCE_DIR}/include/civetweb.h
  DESTINATION include
  COMPONENT c-library)

# Need Windows sockets if available
find_package(WinSock)
if (WINSOCK_FOUND)
  target_link_libraries(c-library WINSOCK::WINSOCK)
endif()

# We need threading
find_package(Threads)
target_link_libraries(c-library ${CMAKE_THREAD_LIBS_INIT})

# We need to link OpenSSL if not dynamically loading
if (CIVETWEB_ENABLE_SSL)
  if (CIVETWEB_ENABLE_SSL_DYNAMIC_LOADING)
    find_package(LibDl)
    if (LIBDL_FOUND)
      target_link_libraries(c-library -ldl)
    endif()
  else()
    find_package(OpenSSL)
    include_directories(${OPENSSL_INCLUDE_DIR})
    message(STATUS "OpenSSL include directory: ${OPENSSL_INCLUDE_DIR}")
    target_link_libraries(c-library ${OPENSSL_LIBRARIES})
  endif()
endif()

# The web server executable
add_executable(c-executable main.c)
set_target_properties(c-executable PROPERTIES
  OUTPUT_NAME "civetweb"
)
install(
  TARGETS c-executable
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib
  RUNTIME DESTINATION bin
  COMPONENT server)
if (BUILD_SHARED_LIBS)
  target_compile_definitions(c-executable PRIVATE CIVETWEB_DLL_IMPORTS)
endif()
target_include_directories(
  c-executable PUBLIC
  ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(c-executable c-library)
