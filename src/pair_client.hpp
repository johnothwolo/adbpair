//
//  pair_client.hpp
//  qrterm
//
//  Created by John Othwolo on 3/5/23.
//  Copyright © 2023 John Othwolo. All rights reserved.
//

#ifndef pair_client_hpp
#define pair_client_hpp

#include <vector>
#include <string>
#include <functional>

int adb_wifi_pair_device(const std::string& ip_addr, unsigned short port, const std::string& password);

#endif /* pair_client_hpp */
