/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "adb_env.hpp"

#  include <cwchar>
#  include <stdexcept>
#  include <locale>
#  include <string>
#include <xlocale.h>

#ifdef _WIN32
#  include <lmcons.h>
#  include <windows.h>
#else
#  include <unistd.h>
#endif  // _WIN32


std::string to_string(wchar_t const* wcstr)
{
    auto s = std::mbstate_t();
    auto const target_char_count = std::wcsrtombs(nullptr, &wcstr, 0, &s);
    if(target_char_count == static_cast<std::size_t>(-1)){
        throw std::logic_error("Illegal byte sequence");
    }

    // +1 because std::string adds a null terminator which isn't part of size
    auto str = std::string(target_char_count, '\0');
    std::wcsrtombs(const_cast<char*>(str.data()), &wcstr, str.size() + 1, &s);
    return str;
}

std::wstring to_wstring(char const* cstr)
{
    auto s = std::mbstate_t();
    auto const target_char_count = std::mbsrtowcs(nullptr, &cstr, 0, &s);
    if(target_char_count == static_cast<std::size_t>(-1)){
        throw std::logic_error("Illegal byte sequence");
    }

    // +1 because std::string adds a null terminator which isn't part of size
    auto wstr = std::wstring(target_char_count, '\0');
    std::mbsrtowcs(const_cast<wchar_t*>(wstr.data()), &cstr, wstr.size() + 1, &s);
    return wstr;
}

std::string GetEnvironmentVariable(std::string_view var)
{
    if (var.empty()) {
        return "";
    }
    
#ifdef _WIN32
    constexpr size_t kMaxEnvVarSize = 32767;
    wchar_t wbuf[kMaxEnvVarSize];
    std::wstring wvar = to_wstring(var.data());
    auto sz = ::GetEnvironmentVariableW(wvar.data(), wbuf, sizeof(wbuf));
    if (sz == 0) {
        return "";
    }
    return to_string(wbuf);
#else  // !_WIN32
    const char* val = getenv(var.data());
    if (val == nullptr) {
        return {};
    }
    return std::string(val);
#endif
}

#ifdef _WIN32
constexpr char kHostNameEnvVar[] = "COMPUTERNAME";
constexpr char kUserNameEnvVar[] = "USERNAME";
#else
constexpr char kHostNameEnvVar[] = "HOSTNAME";
constexpr char kUserNameEnvVar[] = "LOGNAME";
#endif

std::string GetHostNameUTF8()
{
    const auto hostName = GetEnvironmentVariable(kHostNameEnvVar);
    if (!hostName.empty()) {
        return hostName;
    }

#ifdef _WIN32
    wchar_t wbuf[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(wbuf);
    if (!GetComputerNameW(wbuf, &size) || size == 0) {
        return "";
    }

    return to_string(wbuf);
#else   // !_WIN32
    char buf[256];
    return (gethostname(buf, sizeof(buf)) == -1) ? "" : buf;
#endif  // _WIN32
}

std::string GetLoginNameUTF8()
{
    const auto userName = GetEnvironmentVariable(kUserNameEnvVar);
    if (!userName.empty()) {
        return userName;
    }

#ifdef _WIN32
    wchar_t wbuf[UNLEN + 1];
    DWORD size = sizeof(wbuf);
    if (!GetUserNameW(wbuf, &size) || size == 0) {
        return "";
    }
    
    return to_string(wbuf);
#else   // !_WIN32
    const char* login = getlogin();
    return login ? login : "";
#endif  // _WIN32
}
