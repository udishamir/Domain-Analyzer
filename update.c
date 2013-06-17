#include <stdio.h>
#include <curl/curl.h>
//#include <curl/types.h>
#include <curl/easy.h>

#include "update.h"

const char update_url[] = "https://raw.github.com/udishamir/Domain-Analyzer/master/";

const char *update_files[] = {"asn.conf", "wlist.conf", "def.conf", NULL};

int download_file(char *dest, char *url)
{
    CURL *curl;
    FILE *fh;
    curl  = curl_easy_init();

    if (!curl)
        return -1;

    fh = fopen(dest, "wb");
    if (NULL == fh)
        return -2;

    // TODO: check errors?
    curl_easy_setopt(curl, CURLOPT_URL, url);
    //curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, url);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)fh);

    curl_easy_perform(curl);

    curl_easy_cleanup(curl);

    return 0;
}

int update(char* download_path)
{
    char remote_file[256];
    char local_file[256];
    int i;
    int result = 0;

    for (i = 0; update_files[i] ; i++)
    {
        strncpy(remote_file, update_url, sizeof(remote_file));
        strncat(remote_file, update_files[i], sizeof(remote_file) - sizeof(update_url));

        strncpy(local_file, download_path, sizeof(local_file));
        strncat(local_file, update_files[i], sizeof(local_file) - strlen(download_path));

        printf("Downloading '%s' to '%s'", remote_file, local_file);
        result = download_file(local_file, remote_file);
        printf(" returns: %d\n", result);
    }

    return 0;
}
