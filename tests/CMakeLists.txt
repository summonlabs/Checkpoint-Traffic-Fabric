# Test surfaces. Each suite is an independent executable so a failure is
# attributable, and each is registered plainly with CTest: no timeouts, no
# retries, no filtering that could hide a hang.

set(CTF_TEST_SUITES
  unit
  protocol
  integration
  property
  concurrency
  adversarial
  persistence
  multiprocess
  scale)

if(TARGET ctf-coordinator)
  set(CTF_APP_DIR $<TARGET_FILE_DIR:ctf-coordinator>)
else()
  set(CTF_APP_DIR ${CMAKE_BINARY_DIR})
endif()

foreach(suite ${CTF_TEST_SUITES})
  add_executable(ctf_${suite}_tests ${suite}_tests.cpp)
  target_link_libraries(ctf_${suite}_tests PRIVATE ctf)
  ctf_apply_warnings(ctf_${suite}_tests)
  target_include_directories(ctf_${suite}_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/harness)
  target_compile_definitions(ctf_${suite}_tests
    PRIVATE CTF_APP_DIRECTORY="${CTF_APP_DIR}")
  add_test(NAME ctf_${suite}_tests COMMAND ctf_${suite}_tests)
  set_tests_properties(ctf_${suite}_tests PROPERTIES
    LABELS "${suite}"
    SKIP_RETURN_CODE 77)
endforeach()

# Cross-suite aggregate: runs every suite in one CTest invocation when asked.
add_test(NAME ctf_all_suites COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target help)
set_tests_properties(ctf_all_suites PROPERTIES DISABLED TRUE)
