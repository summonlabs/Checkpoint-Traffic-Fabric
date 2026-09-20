add_executable(ctf-coordinator ctf-coordinator/main.cpp)
target_link_libraries(ctf-coordinator PRIVATE ctf)
target_include_directories(ctf-coordinator PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
ctf_apply_warnings(ctf-coordinator)

add_executable(ctf-agent ctf-agent/main.cpp)
target_link_libraries(ctf-agent PRIVATE ctf)
target_include_directories(ctf-agent PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
ctf_apply_warnings(ctf-agent)

add_executable(ctfctl ctfctl/main.cpp)
target_link_libraries(ctfctl PRIVATE ctf)
target_include_directories(ctfctl PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
ctf_apply_warnings(ctfctl)

install(TARGETS ctf-coordinator ctf-agent ctfctl
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
