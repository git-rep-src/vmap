#include "net.h"

#include <curl/curl.h>
#include <curl/easy.h>

size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
    std::string data((const char*) ptr, (size_t) size * nmemb);
    *((std::stringstream*) stream) << data;
    
    return size * nmemb;
}

Net::Net()
{
    curl = curl_easy_init();
}

Net::~Net()
{
    curl_easy_cleanup(curl);
}

bool Net::get(const std::string &url, std::stringstream *ret)
{
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
        curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "deflate");
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, ret);
    
        CURLcode res = curl_easy_perform(curl);
    
        if (res != CURLE_OK)
            return false;
    } else {
        return false;
    }

    return true;
}
