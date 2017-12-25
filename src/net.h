#ifndef NET_H
#define NET_H

#include <string>
#include <sstream>

class Net
{
public:
    Net();
    ~Net();
    
    bool get(const std::string &url, std::stringstream *ret);

private:
    void *curl;
};

#endif // NET_H
