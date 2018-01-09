# ECC Utilities

include(CheckCXXCompilerFlag)

# Set policy if policy is available
function(set_policy POL VAL)
  if(POLICY ${POL})
    cmake_policy(SET ${POL} ${VAL})
  endif()
endfunction(set_policy)

# Check C++ version
macro(project_check_cpp_version)
  if (NOT MSVC)
    # Tests for Clang and GCC
    check_cxx_compiler_flag(-std=c++1y CPP14_SUPPORT)
    if (CPP14_SUPPORT)
      set(CPP11_SUPPORT TRUE)
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1y")
      message("-- C++14 support found.")
    else()
      check_cxx_compiler_flag(-std=c++11 CPP11_SUPPORT)
      if (CPP11_SUPPORT)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
        message("-- C++11 support found.")
      endif()
    endif()
  else()
    # Tests for MSVC
    # Unfortunately, due to various unsupported things in msvc versions,
    # this is poor informatiion about actual support
    check_cxx_source_compiles("#include <utility>\nusing std::integer_sequence;\n int main(){return 0;}" CPP14_SUPPORT)
    if (CPP14_SUPPORT)
      set(CPP11_SUPPORT TRUE)
      message("-- C++14 support found.")
    else()
      check_cxx_source_compiles("static constexpr int TEST=0;\n int main(){return 0;}" CPP11_SUPPORT)
      if (CPP11_SUPPORT)
        message("-- C++11 support found.")
      endif()
    endif ()
  endif()
endmacro(project_check_cpp_version)