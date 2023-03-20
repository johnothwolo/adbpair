/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "adb_utils.hpp"

#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <iostream>
#include <vector>

#ifdef _WIN32
#  include <windows.h>
#  include <shlobj.h>
#  include <system_error>
#  include <locale>
#  include <codecvt>
#else
#  include <pwd.h>
#endif

#if defined(_WIN32)
static constexpr char kNullFileName[] = "NUL";
#else
static constexpr char kNullFileName[] = "/dev/null";
#endif


bool getcwd(std::string* s) {
  char* cwd = getcwd(nullptr, 0);
  if (cwd != nullptr) *s = cwd;
  free(cwd);
  return (cwd != nullptr);
}

bool directory_exists(const std::string& path) {
  struct stat sb;
  return stat(path.c_str(), &sb) != -1 && S_ISDIR(sb.st_mode);
}

std::string escape_arg(const std::string& s) {
  // Escape any ' in the string (before we single-quote the whole thing).
  // The correct way to do this for the shell is to replace ' with '\'' --- that is,
  // close the existing single-quoted string, escape a single single-quote, and start
  // a new single-quoted string. Like the C preprocessor, the shell will concatenate
  // these pieces into one string.

  std::string result;
  result.push_back('\'');

  size_t base = 0;
  while (true) {
    size_t found = s.find('\'', base);
    result.append(s, base, found - base);
    if (found == s.npos) break;
    result.append("'\\''");
    base = found + 1;
  }

  result.push_back('\'');
  return result;
}

std::string adb_get_homedir_path() {
#ifdef _WIN32
    WCHAR path[MAX_PATH];
    const HRESULT hr = SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, path);
    if (FAILED(hr)) {
        printf("SHGetFolderPathW failed: %s", std::system_category().message(::GetLastError()));
        return {};
    }
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>,char16_t> convert;
    std::string home_str = convert.to_bytes(path);
    
    if (home_str.empty()) {
        return {};
    }
    return home_str;
#else

    if (const char* const home = getenv("HOME")) {
        return home;
    }

    struct passwd pwent;
    struct passwd* result;
    int pwent_max = (int)sysconf(_SC_GETPW_R_SIZE_MAX);
    if (pwent_max == -1) {
        pwent_max = 16384;
    }
    std::vector<char> buf(pwent_max);
    int rc = getpwuid_r(getuid(), &pwent, buf.data(), buf.size(), &result);
    if (rc == 0 && result) {
        return result->pw_dir;
    }

    std::cerr << "failed to get user home directory";
    return {};
#endif
}

std::string adb_get_android_dir_path() {
    std::string user_dir = adb_get_homedir_path();
    std::string android_dir = user_dir + OS_PATH_SEPARATOR + ".android";
    struct stat buf;
    if (stat(android_dir.c_str(), &buf) == -1) {
        if (mkdir(android_dir.c_str(), 0750) == -1) {
            std::cerr << "Cannot mkdir '" << android_dir << "'";
        }
    }
    return android_dir;
}

[[noreturn]] static void error_exit_va(int error, const char* fmt, va_list va) {
    fflush(stdout);
    fprintf(stderr, "%s: ", "adb_wifipair"); // FIXME: export argv[0] and use it here.

    vfprintf(stderr, fmt, va);

    if (error != 0) {
        fprintf(stderr, ": %s", strerror(error));
    }

    putc('\n', stderr);
    fflush(stderr);

    exit(EXIT_FAILURE);
}

void error_exit(const char* fmt, ...) {
    va_list va;
    va_start(va, fmt);
    error_exit_va(0, fmt, va);
    va_end(va);
}

void perror_exit(const char* fmt, ...) {
    va_list va;
    va_start(va, fmt);
    error_exit_va(errno, fmt, va);
    va_end(va);
}
