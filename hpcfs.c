// HPCFS FUSE module
// 08/2009 - Dailymotion/PYKE

// Mandatory includes
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <pcre.h>
#include <fuse.h>

// Defines and directives
#pragma pack(1)

#define MODULE_VERSION       "1.0.0"

#define MAXIMUM_REWRITES     (32)
#define MAXIMUM_HOSTMAPS     (32)
#define MAXIMUM_HOSTENTRIES  (32)
#define MAXIMUM_HOSTS        (32)
#define MAXIMUM_MATCHES      (32)
#define MAXIMUM_DEPTH        (8)
#define CONNECT_TIMEOUT      (5)
#define MAP_TIMEOUT          (5)
#define RECEIVE_TIMEOUT      (30)
#define STALE_TIMEOUT        (30)

#define CLIENT_CLOSED        (0)
#define CLIENT_OPENED        (1)
#define CLIENT_CONNECTING    (2)
#define CLIENT_CONNECTED     (3)
#define CLIENT_REQUESTED     (4)
#define CLIENT_RESPONDED     (5)

#define LINE_SIZE            (1024)
#define BUFFER_SIZE          (64 * 1024)

// URI record
typedef struct
{
    char        url[LINE_SIZE];
    char        *scheme;
    char        *hostname;
    u_int16_t   port;
    char        service[16];
    char        *path;
    char        *query;
    char        *fragment;
} uri_t;

// Poller record
typedef struct
{
    u_int32_t     count;
    struct pollfd fds[MAXIMUM_HOSTMAPS];
    void          *data[MAXIMUM_HOSTMAPS];
} poller_t;

// Client record
typedef struct
{
    u_int32_t   state;
    u_int32_t   last;
    u_int32_t   retries;
    u_int32_t   start;
    u_int32_t   responded;
    char        *hostname;
    int         socket;
} client_t;

// Hostentry record
typedef struct
{
    u_int32_t   count;
    char        *hosts[MAXIMUM_HOSTS];
} hostentry_t;

// Hostmap record
typedef struct
{
    char        *name;
    u_int32_t   count;
    hostentry_t entries[MAXIMUM_HOSTENTRIES];
} hostmap_t;

// Rewrite record
typedef struct
{
    pcre        *regex;
    char        *value;
} rewrite_t;

// Module globals
static u_int32_t        hpcfs_hostmaps_count      = 0;
static hostmap_t        hpcfs_hostmaps[MAXIMUM_HOSTMAPS];

static u_int32_t        hpcfs_rewrites_count      = 0;
static rewrite_t        hpcfs_rewrites[MAXIMUM_REWRITES];

static u_int32_t        hpcfs_connect_timeout     = CONNECT_TIMEOUT;
static u_int32_t        hpcfs_map_timeout         = MAP_TIMEOUT;
static u_int32_t        hpcfs_receive_timeout     = RECEIVE_TIMEOUT;
static u_int32_t        hpcfs_max_depth           = MAXIMUM_DEPTH;

static char             *hpcfs_cache_root         = NULL;

static char             *hpcfs_log                = NULL;
static char             hpcfs_log_path[LINE_SIZE] = {0};
static pthread_mutex_t  hpcfs_log_mutex           = PTHREAD_MUTEX_INITIALIZER;
static int              hpcfs_log_handle          = -1;
static time_t           hpcfs_log_last            = 0;

// Trim a string in-place and remove comments (#-started strings)
static char *hpcfs_trim(char *value, const char *characters)
{
    char *token, protected = 0;

    if (! value)
    {
        return value;
    }
    if (! characters)
    {
        characters = "\n\r\t ";
    }
    token = value;
    while (*token)
    {
        if (*token == '"' && ((token == value) || (*(token - 1) != '\\')))
        {
            protected = 1 - protected;
        }
        if (! protected && *token == '#')
        {
            *token = 0;
            break;
        }
        token ++;
    }
    token = value + strlen(value) - 1;
    while (token >= value && strchr(characters, *token))
    {
        *token = 0;
        token --;
    }
    while (*value && strchr(characters, *value))
    {
        memmove(value, value + 1, strlen(value) + 1);
    }
    return value;
}

// Create a directory recursively
static int hpcfs_directory(const char *path)
{
    struct stat info;
    char   prefix[LINE_SIZE], *token;
    int    index, part = 0;

    if (! stat(path, &info) && S_ISDIR(info.st_mode))
    {
        return 0;
    }
    memset(prefix, sizeof(prefix), 0);
    while (1)
    {
        strncpy(prefix, path, sizeof(prefix) - 1);
        index = 0;
        token = prefix + 1;
        while ((token = strchr(token, '/')) && index++ < part)
        {
            token ++;
        }
        if (token)
        {
           *token = 0;
        }
        mkdir(prefix, 0755);
        if (! token)
        {
            break;
        }
        part ++;
    }
    if (stat(path, &info) < 0 || ! S_ISDIR(info.st_mode))
    {
        return -1;
    }
    return 0;
}

// Substitute strings from regex matches
static void hpcfs_substitute(char *target, u_int32_t size, const char *source, int *matches)
{
    char      reference[4], *token;
    u_int32_t index, length;

    for (index = MAXIMUM_MATCHES - 1; index >= 1; index --)
    {
        sprintf(reference, "$%d", index);
        length = strlen(reference);
        while ((token = strstr(target, reference)))
        {
            if (matches[index * 2] >= 0 && matches[(index * 2) + 1] >= 0)
            {
                if (strlen(target) - 2 + (matches[(index * 2) + 1] - matches[index * 2]) < size)
                {
                    memmove(token + matches[(index * 2) + 1] - matches[index * 2], token + length, strlen(token + length) + 1);
                    memcpy(token, source + matches[index * 2], matches[(index * 2) + 1] - matches[index * 2]);
                }
                else
                {
                    memmove(token, token + length, strlen(token + length) + 1);
                }
            }
            else
            {
                memmove(token, token + length, strlen(token + length) + 1);
            }
        }
    }
}

// Parse URL into components
static int hpcfs_parse_uri(char *url, uri_t *uri)
{
    char *token;

    if (! url || ! uri || ! url[0])
    {
        return -1;
    }
    memset(uri, 0, sizeof(uri_t));
    strncpy(uri->url, url, LINE_SIZE - 2);
    uri->scheme   = uri->url + LINE_SIZE - 1;
    uri->hostname = uri->scheme;
    uri->port     = 80;
    strcpy(uri->service, "80");
    uri->path     = uri->scheme;
    uri->query    = uri->scheme;
    uri->fragment = uri->scheme;
    if (! (token = strstr(uri->url, "://")))
    {
        return -1;
    }
    *token = 0;
    uri->scheme   = uri->url;
    uri->hostname = token + 3;
    if (! (token = strchr(uri->hostname, '/')))
    {
        return -1;
    }
    memmove(token + 1, token, strlen(token) + 1);
    uri->path = token + 1;
    *token    = 0;
    if ((token = strchr(uri->hostname, ':')))
    {
        *token = 0;
        uri->port = atoi(token + 1);
        sprintf(uri->service, "%d", uri->port);
    }
    if (! uri->port)
    {
        return -1;
    }
    if ((token = strrchr(uri->path, '#')))
    {
        *token = 0;
        uri->fragment = token + 1;
    }
    if ((token = strrchr(uri->path, '?')))
    {
        *token = 0;
        uri->query = token + 1;
    }
    return 0;
}

// Log a timestamped message
static void hpcfs_write_log(const char *format, ...)
{
    va_list   arguments;
    struct tm current;
    time_t    now;
    char      line[LINE_SIZE], path[LINE_SIZE], *token;

    if (! hpcfs_log || ! hpcfs_log[0])
    {
        return;
    }
    now = time(NULL);
    localtime_r(&now, &current);
    sprintf(line, "%04d-%02d-%02d %02d:%02d:%02d|",
            current.tm_year + 1900, current.tm_mon + 1, current.tm_mday,
            current.tm_hour, current.tm_min, current.tm_sec);
    va_start(arguments, format);
    vsnprintf(line + 20, sizeof(line) - 20 - 2, format, arguments);
    va_end(arguments);
    strcat(line, "\n");
    if (now != hpcfs_log_last)
    {
        hpcfs_log_last = now;
        strftime(path, sizeof(path) - 1, hpcfs_log, &current);
        if (strcmp(path, hpcfs_log_path))
        {
            strcpy(hpcfs_log_path, path);
            if ((token = strrchr(hpcfs_log_path, '/')))
            {
                *token = 0;
                hpcfs_directory(hpcfs_log_path);
                *token = '/';
            }
            if (hpcfs_log_handle >= 0)
            {
                close(hpcfs_log_handle);
                hpcfs_log_handle = -1;
            }
        }
    }
    if (hpcfs_log_handle < 0)
    {
        if ((hpcfs_log_handle = open(hpcfs_log_path, O_CREAT | O_WRONLY | O_APPEND, 0644)) < 0)
        {
            hpcfs_log_handle = -1;
        }
    }
    if (hpcfs_log_handle >= 0)
    {
        if (! pthread_mutex_lock(&hpcfs_log_mutex))
        {
            if (write(hpcfs_log_handle, line, strlen(line))) {}
            pthread_mutex_unlock(&hpcfs_log_mutex);
        }
    }
}

// Parse configuration file
static int hpcfs_parse_configuration(const char *path)
{
    struct stat info;
    rewrite_t   *rewrite;
    hostmap_t   *hostmap;
    hostentry_t *hostentry;
    FILE        *configuration = NULL;
    char        line[LINE_SIZE], target[LINE_SIZE], *name, *value, *token1, *token2, *token3, *token4, *token5, *token6;
    int         count = 0, index, start, end;

    if (! (configuration = fopen(path, "r")))
    {
        fprintf(stderr, "hpcfs: cannot open configuration file %s\n", path);
        return 1;
    }
    while (fgets(line, sizeof(line), configuration))
    {
        count ++;
        hpcfs_trim(line, NULL);
        if (! *line)
        {
            continue;
        }
        name  = hpcfs_trim(strtok(line, " \t"), NULL);
        value = hpcfs_trim(strtok(NULL, " \t"), NULL);
        if (! value || ! *value)
        {
            fprintf(stderr, "hpcfs: missing value for directive %s at line %d\n", name, count);
            return 1;
        }
        if (! strcasecmp(name, "HostMap"))
        {
            if (hpcfs_hostmaps_count < MAXIMUM_HOSTMAPS)
            {
                for (index = 0; index < hpcfs_hostmaps_count; index ++)
                {
                    if (! strcasecmp(value, hpcfs_hostmaps[index].name))
                    {
                        fprintf(stderr, "hpcfs: duplicate hostmap name %s at line %d\n", value, count);
                        return 1;
                    }
                }
                hostmap       = &(hpcfs_hostmaps[hpcfs_hostmaps_count]);
                hostmap->name = strdup(value);
                value         = hpcfs_trim(strtok(NULL, "\""), NULL);
                token1 = strtok_r(value, " \t", &token2);
                while (token1 && hostmap->count < MAXIMUM_HOSTENTRIES)
                {
                    hostentry = &(hostmap->entries[hostmap->count]);
                    token3    = strtok_r(token1, ",", &token4);
                    while (token3 && hostentry->count < MAXIMUM_HOSTS)
                    {
                        if ((token5 = strstr(token3, "$[")))
                        {
                            if (sscanf(token5 + 2, "%u-%u]", &start, &end) != 2 || ! (token6 = strchr(token5, ']')) ||
                                start > 255 || end > 255 || start > end || strlen(token3) >= sizeof(target) - 1)
                            {
                                fprintf(stderr, "hpcfs: invalid hostmap value at line %d\n", count);
                                return 1;
                            }
                            memcpy(target, token3, token5 - token3);
                            for (index = start; index <= end && hostentry->count < MAXIMUM_HOSTS; index ++)
                            {
                                sprintf(target + (token5 - token3), "%d", index);
                                strcat(target, token6 + 1);
                                hostentry->hosts[hostentry->count] = strdup(target);
                                hostentry->count ++;
                            }
                        }
                        else
                        {
                            hostentry->hosts[hostentry->count] = strdup(token3);
                            hostentry->count ++;
                        }
                        token3 = strtok_r(NULL, ",", &token4);
                    }
                    token1 = strtok_r(NULL, " \t", &token2);
                    hostmap->count ++;
                }
                hpcfs_hostmaps_count ++;
            }
        }
        else if (! strcasecmp(name, "Rewrite"))
        {
            if (hpcfs_rewrites_count < MAXIMUM_REWRITES)
            {
                rewrite = &(hpcfs_rewrites[hpcfs_rewrites_count]);
                if (! (rewrite->regex = pcre_compile(value, PCRE_CASELESS, (const char **)&token1, &index, NULL)))
                {
                     fprintf(stderr, "hpcfs: invalid regex %s at line %d (%s)\n", value, count, token1);
                     return 1;
                }
                rewrite->value = strdup(hpcfs_trim(strtok(NULL, ""), "\n\r\t \""));
                hpcfs_rewrites_count ++;
            }
        }
        else if (! strcasecmp(name, "ConnectTimeout"))
        {
            hpcfs_connect_timeout = atoi(value);
            hpcfs_connect_timeout = hpcfs_connect_timeout < 1 ? 1 : hpcfs_connect_timeout;
            hpcfs_connect_timeout = hpcfs_connect_timeout > 60 ? 60 : hpcfs_connect_timeout;
        }
        else if (! strcasecmp(name, "MapTimeout"))
        {
            hpcfs_map_timeout = atoi(value);
            hpcfs_map_timeout = hpcfs_map_timeout < 1 ? 1 : hpcfs_map_timeout;
            hpcfs_map_timeout = hpcfs_map_timeout > 60 ? 60 : hpcfs_map_timeout;
        }
        else if (! strcasecmp(name, "ReceiveTimeout"))
        {
            hpcfs_receive_timeout = atoi(value);
            hpcfs_receive_timeout = hpcfs_receive_timeout < 10 ? 10 : hpcfs_receive_timeout;
            hpcfs_receive_timeout = hpcfs_receive_timeout > 300 ? 300 : hpcfs_receive_timeout;
        }
        else if (! strcasecmp(name, "MaxDepth"))
        {
            hpcfs_max_depth = atoi(value);
            hpcfs_max_depth = hpcfs_max_depth < 1 ? 1 : hpcfs_max_depth;
            hpcfs_max_depth = hpcfs_max_depth > 16 ? 16 : hpcfs_max_depth;
        }
        else if (! strcasecmp(name, "CacheRoot"))
        {
            if (stat(value, &info) || ! S_ISDIR(info.st_mode))
            {
                fprintf(stderr, "hpcfs: invalid CacheRoot value %s at line %d\n", value, count);
               return 1;
            }
            hpcfs_cache_root = strdup(value);
        }
        else if (! strcasecmp(name, "Log"))
        {
            hpcfs_log = strdup(value);
        }
        else
        {
            fprintf(stderr, "hpcfs: unknown directive %s at line %d\n", name, count);
            return 1;
        }
    }
    fclose(configuration);
    return 0;
}

// Perform an "HTTP whohas" lookup
static int hpcfs_poller_add(poller_t *poller, int socket, int events, void *data)
{
    if (! poller || poller->count >= MAXIMUM_HOSTMAPS)
    {
        return -1;
    }
    poller->fds[poller->count].fd     = socket;
    poller->fds[poller->count].events = events;
    poller->data[poller->count]       = data;
    poller->count ++;
    return 0;
}
static int hpcfs_poller_remove(poller_t *poller, int socket)
{
    int index;

    if (! poller || ! poller->count)
    {
        return -1;
    }
    for (index = 0; index < poller->count; index ++)
    {
        if (poller->fds[index].fd == socket)
        {
            break;
        }
    }
    if (index == poller->count)
    {
        return -1;
    }
    if (index < (poller->count - 1))
    {
        memmove(&(poller->fds[index]), &(poller->fds[index + 1]), sizeof(struct pollfd) * (poller->count - index - 1));
        memmove(&(poller->data[index]), &(poller->data[index + 1]), sizeof(void *) * (poller->count - index - 1));
    }
    poller->count --;
    return 0;
}
static void hpcfs_connect(hostentry_t *hostentry, client_t *client, char *service, poller_t *poller)
{
    struct addrinfo *address = NULL;

    if (client->state)
    {
        hpcfs_poller_remove(poller, client->socket);
        close(client->socket);
        client->state = CLIENT_CLOSED;
    }
    while (client->retries < hostentry->count)
    {
        if (address)
        {
            freeaddrinfo(address);
        }
        if (! client->retries)
        {
            client->last = rand() % hostentry->count;
        }
        else
        {
            client->last ++;
            if (client->last >= hostentry->count)
            {
                client->last = 0;
            }
        }
        client->retries ++;
        if (getaddrinfo(hostentry->hosts[client->last], service, NULL, &address) ||
            (client->socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
            continue;
        }
        if (fcntl(client->socket, F_SETFL, fcntl(client->socket, F_GETFL) | O_NONBLOCK) < 0)
        {
            close(client->socket);
            continue;
        }
        client->state    = CLIENT_OPENED;
        client->hostname = hostentry->hosts[client->last];
        client->start    = time(NULL);
        if (connect(client->socket, address->ai_addr, address->ai_addrlen) < 0)
        {
            if (errno == EINPROGRESS)
            {
                client->state = CLIENT_CONNECTING;
                hpcfs_poller_add(poller, client->socket, POLLOUT, client);
                break;
            }
            else
            {
                close(client->socket);
                client->state = CLIENT_CLOSED;
            }
        }
        else
        {
            client->state = CLIENT_CONNECTED;
            break;
        }
    }
    if (address)
    {
        freeaddrinfo(address);
    }
}
static int hpcfs_whohas(uri_t *uri, char *host, u_int32_t size)
{
    hostmap_t          *hostmap;
    poller_t           poller;
    client_t           clients[MAXIMUM_HOSTENTRIES], *client;
    time_t             now;
    u_int32_t          index;
    u_int16_t          events;
    int                status, received;
    char               line[LINE_SIZE];

    if (!uri || ! host || ! size)
    {
        return -1;
    }
    memset(host, 0, size);
    if (memcmp(uri->hostname, "${", 2) || uri->hostname[strlen(uri->hostname) - 1] != '}')
    {
        strncpy(host, uri->hostname, size - 1);
        return 0;
    }
    memset(clients, 0, sizeof(clients));
    strncpy(line, uri->hostname + 2, sizeof(line) - 1);
    line[strlen(line) - 1] = 0;
    for (index = 0; index < hpcfs_hostmaps_count; index ++)
    {
        if (! strcasecmp(line, hpcfs_hostmaps[index].name))
        {
            break;
        }
    }
    if (index == hpcfs_hostmaps_count)
    {
        return -1;
    }
    memset(host, 0, size);
    memset(&poller, 0, sizeof(poller));
    hostmap = &(hpcfs_hostmaps[index]);
    for (index = 0; index < hostmap->count; index ++)
    {
        hpcfs_connect(&(hostmap->entries[index]), &(clients[index]), uri->service, &poller);
    }
    while (! host[0])
    {
        now = time(NULL);
        for (index = 0; index < hostmap->count; index++)
        {
            client = &(clients[index]);
            if (! client->state)
            {
                continue;
            }
            if (! client->responded && (now - client->start) >= hpcfs_map_timeout)
            {
                hpcfs_connect(&(hostmap->entries[index]), client, uri->service, &poller);
            }
            if (client->state == CLIENT_CONNECTED)
            {
                fcntl(client->socket, F_SETFL, fcntl(client->socket, F_GETFL) & ~O_NONBLOCK);
                snprintf(line, sizeof(line) - 1,
                         "HEAD %s%s%s%s%s HTTP/1.1\r\n"
                         "User-Agent: hpcfs/%s\r\n"
                         "Host: %s\r\n"
                         "Accept: */*\r\n"
                         "\r\n",
                         uri->path,
                         uri->query[0] ? "?" : "",
                         uri->query[0] ? uri->query : "",
                         uri->fragment[0] ? "#" : "",
                         uri->fragment[0] ? uri->fragment : "",
                         MODULE_VERSION,
                         client->hostname);
                if (write(client->socket, line, strlen(line))) {}
                client->state = CLIENT_REQUESTED;
                hpcfs_poller_add(&poller, client->socket, POLLIN, client);
            }
        }
        if (! poller.count)
        {
            break;
        }
        if ((status = poll(poller.fds, poller.count, 1000)) < 0)
        {
            break;
        }
        if (! status)
        {
            continue;
        }
        for (index = 0; index < poller.count; index ++)
        {
            if ((events = poller.fds[index].revents))
            {
                client = poller.data[index];
                hpcfs_poller_remove(&poller, client->socket);
                if (client->state == CLIENT_CONNECTING && (events & POLLOUT))
                {
                    client->state = CLIENT_CONNECTED;
                }
                if (client->state == CLIENT_REQUESTED && (events & (POLLIN | POLLHUP)))
                {
                    client->state = CLIENT_RESPONDED;
                    if ((received = read(client->socket, line, sizeof(line) - 1)) > 0)
                    {
                        line[received] = 0;
                        if (! memcmp(line, "HTTP/1.", 7) && sscanf(line + 9, "%d", &status))
                        {
                            client->responded = 1;
                            if (status == 200 || status == 301 || status == 302 || status == 303)
                            {
                                strncpy(host, client->hostname, size - 1);
                                break;
                            }
                        }
                    }
                    close(client->socket);
                    client->state = CLIENT_CLOSED;
                }
                if (events & (POLLERR | POLLNVAL))
                {
                    hpcfs_connect(&(hostmap->entries[index]), &(clients[index]), uri->service, &poller);
                }
            }
        }
    }
    for (index = 0; index < hostmap->count; index ++)
    {
        client = &(clients[index]);
        if (client->state != CLIENT_CLOSED)
        {
            close(client->socket);
        }
    }
    return host[0] ? 0 : -1;
}

// Get FS node attributes
static int hpcfs_getattr(const char *path, struct stat *finfo)
{
    uri_t           uri;
    struct stat     info;
    struct addrinfo *address = NULL;
    struct pollfd   poller;
    char            cache[LINE_SIZE], target[LINE_SIZE], host[LINE_SIZE], buffer[BUFFER_SIZE], *token1, *token2, *token3;
    u_int64_t       total = 0, remaining;
    u_int32_t       index, depth = 0, code, offset, size;
    int             matches[MAXIMUM_MATCHES * 3], client = -1, output, received, status = -ENOENT;

    snprintf(cache, sizeof(cache) - 1, "%s%s_active", hpcfs_cache_root, path);
    if (! stat(cache, &info) && S_ISREG(info.st_mode))
    {
        if (info.st_mtime > (time(NULL) - STALE_TIMEOUT))
        {
            while (1)
            {
                sleep(1);
                if (stat(cache, &info) || info.st_mtime <= (time(NULL) - STALE_TIMEOUT))
                {
                    break;
                }
            }
            if (! stat(cache, &info) && info.st_mtime <= (time(NULL) - STALE_TIMEOUT))
            {
                unlink(cache);
            }
        }
        else
        {
            unlink(cache);
        }
    }
    cache[strlen(cache) - 7] = 0;
    if (! stat(cache, &info) && (S_ISDIR(info.st_mode) || S_ISREG(info.st_mode)))
    {
        memcpy(finfo, &info, sizeof(info));
        finfo->st_size = 4096;
        finfo->st_mode = 0755 | (S_ISDIR(info.st_mode) ? S_IFDIR : S_IFLNK);
        if (S_ISREG(info.st_mode))
        {
            hpcfs_write_log("CACHE-OUT|%s", cache);
        }
        return 0;
    }
    strcat(cache, "_active");
    memset(finfo, 0, sizeof(struct stat));
    finfo->st_nlink = 1;
    finfo->st_size  = 4096;
    finfo->st_uid   = getuid();
    finfo->st_gid   = getgid();
    finfo->st_ctime = time(NULL);
    finfo->st_mtime = finfo->st_ctime;
    finfo->st_atime = finfo->st_ctime;
    for (index = 0; index < hpcfs_rewrites_count; index ++)
    {
        memset(matches, -1, MAXIMUM_MATCHES * 3 * sizeof(int));
        if (pcre_exec(hpcfs_rewrites[index].regex, NULL, path, strlen(path), 0, 0, matches, MAXIMUM_MATCHES * 3) > 0)
        {
            break;
        }
    }
    if (index == hpcfs_rewrites_count)
    {
        finfo->st_mode = 0755 | S_IFDIR;
        return 0;
    }
    if ((token1 = strrchr(cache, '/')))
    {
        *token1 = 0;
        if (hpcfs_directory(cache) < 0)
        {
            return -ENOENT;
        }
        *token1 = '/';
    }
    memset(target, 0, sizeof(target));
    strncpy(target, hpcfs_rewrites[index].value, sizeof(target) - 1);
    hpcfs_substitute(target, sizeof(target) - 1, path, matches);
    while (depth < hpcfs_max_depth)
    {
        depth ++;
        size = BUFFER_SIZE;
        if (hpcfs_parse_uri(target, &uri) < 0 ||
            hpcfs_whohas(&uri, host, sizeof(host)) < 0 ||
            getaddrinfo(host, uri.service, NULL, &address) ||
            (client = socket(AF_INET, SOCK_STREAM, 0)) < 0 ||
            setsockopt(client, SOL_SOCKET, SO_RCVBUF, (char *)&size, sizeof(size)) < 0 ||
            fcntl(client, F_SETFL, fcntl(client, F_GETFL) | O_NONBLOCK) < 0)
        {
            break;
        }
        if (connect(client, address->ai_addr, address->ai_addrlen) < 0)
        {
            if (errno != EINPROGRESS)
            {
                break;
            }
            poller.fd     = client;
            poller.events = POLLOUT;
            if (poll(&poller, 1, hpcfs_connect_timeout * 1000) <= 0 || ! (poller.revents & POLLOUT))
            {
                break;
            }
        }
        fcntl(client, F_SETFL, fcntl(client, F_GETFL) & ~O_NONBLOCK);
        snprintf(buffer, sizeof(buffer) - 1,
                 "GET %s%s%s%s%s HTTP/1.1\r\n"
                 "User-Agent: hpcfs/%s\r\n"
                 "Host: %s\r\n"
                 "Accept: */*\r\n\r\n",
                 uri.path,
                 uri.query[0] ? "?" : "",
                 uri.query[0] ? uri.query : "",
                 uri.fragment[0] ? "#" : "",
                 uri.fragment[0] ? uri.fragment : "",
                 MODULE_VERSION,
                 host);
        if (write(client, buffer, strlen(buffer)) < 0)
        {
            break;
        }
        offset    = 0;
        remaining = 0;
        code      = 0;
        while (1)
        {
            if ((size = sizeof(buffer) - offset - 1) < 0)
            {
                break;
            }
            poller.fd     = client;
            poller.events = POLLIN;
            if (poll(&poller, 1, hpcfs_receive_timeout * 1000) <= 0 || ! (poller.revents & POLLIN))
            {
                break;
            }
            if ((received = read(client, buffer + offset, size)) <= 0)
            {
                break;
            }
            offset += received;
            buffer[offset] = 0;
            if ((token1 = strstr(buffer, "\r\n\r\n")))
            {
                remaining = offset - (token1 - buffer + 4);
                *token1   = 0;
                token1    = strtok_r(buffer, "\r\n", &token2);
                while (token1)
                {
                    if (! code)
                    {
                        if (memcmp(token1, "HTTP/", 5) ||
                            ! isdigit(*(token1 + 5)) || *(token1 + 6) != '.' || ! isdigit(*(token1 + 7)) ||
                            *(token1 + 8) != ' ' ||
                            ! isdigit(*(token1 + 9)) || ! isdigit(*(token1 + 10)) || ! isdigit(*(token1 + 11)))
                        {
                            break;
                        }
                        code = atoi(token1 + 9);
                    }
                    else
                    {
                        if ((token3 = strstr(token1, ": ")))
                        {
                            *token3 = 0;
                            token3 += 2;
                            if (! strcmp(token1, "Content-Length"))
                            {
                                total = atoll(token3);
                            }
                            else if (! strcmp(token1, "Location"))
                            {
                                strncpy(target, token3, sizeof(target) - 1);
                            }
                        }
                    }
                    token1 = strtok_r(NULL, "\r\n", &token2);
                }
                break;
            }
        }
        if (code == 200)
        {
            if ((output = open(cache, O_CREAT | O_TRUNC | O_WRONLY | O_EXCL, 0644)) < 0)
            {
                break;
            }
            if (remaining > 0)
            {
                if (write(output, buffer + offset - remaining, remaining) < 0)
                {
                    close(output);
                    break;
                }
            }
            remaining = total - remaining;
            while (remaining > 0 && total > 0)
            {
                poller.fd     = client;
                poller.events = POLLIN;
                if (poll(&poller, 1, hpcfs_receive_timeout * 1000) <= 0 || ! (poller.revents & POLLIN))
                {
                    break;
                }
                if ((received = read(client, buffer, sizeof(buffer))) <= 0)
                {
                    break;
                }
                remaining -= received;
                if (write(output, buffer, received) < 0)
                {
                    break;
                }
            }
            close(output);
            if (remaining > 0)
            {
                unlink(cache);
                break;
            }
            strncpy(buffer, cache, sizeof(buffer) - 1);
            buffer[strlen(buffer) - 7] = 0;
            rename(cache, buffer);
            hpcfs_write_log("CACHE-IN|%s", buffer);
            finfo->st_mode = 0755 | S_IFLNK;
            status         = 0;
            break;
        }
        else if (code != 301 && code != 302 && code != 303)
        {
            break;
        }
        close(client);
        client = - 1;
        freeaddrinfo(address);
        address = NULL;
    }
    if (client >= 0)
    {
        close(client);
    }
    if (address)
    {
        freeaddrinfo(address);
    }
    return status;
}

// Get FS symlink target
static int hpcfs_readlink(const char *path, char *target, size_t size)
{
    struct stat info;

    snprintf(target, size - 1, "%s%s", hpcfs_cache_root, path);
    if (stat(target, &info) || ! S_ISREG(info.st_mode))
    {
        return -ENOENT;
    }
    return 0;
}

// Check FS directory existence from cache
static int hpcfs_opendir(const char *path, struct fuse_file_info *unused)
{
    struct stat info;
    char        line[LINE_SIZE];

    snprintf(line, sizeof(line) - 1, "%s%s", hpcfs_cache_root, path);
    if (stat(line, &info) || ! S_ISDIR(info.st_mode))
    {
        return -ENOENT;
    }
    return 0;
}

// List FS directory entries from cache
static int hpcfs_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t unused1, struct fuse_file_info *unused2)
{
    DIR           *directory;
    struct dirent *entry, *memory = NULL;
    char          line[LINE_SIZE];
    int           length;

    snprintf(line, sizeof(line) - 1, "%s%s", hpcfs_cache_root, path);
    if (! (directory = opendir(line)))
    {
        return -ENOENT;
    }
    if (! (entry = malloc(offsetof(struct dirent, d_name) + pathconf(line, _PC_NAME_MAX) + 1)))
    {
        closedir(directory);
        return -ENOSYS;
    }
    while (! readdir_r(directory, entry, &memory) && memory)
    {
        length = strlen(entry->d_name);
        if (length < 8 || memcmp(entry->d_name + length - 7, "_active", 7))
        {
            filler(buffer, entry->d_name, NULL, 0);
        }
    }
    free(entry);
    closedir(directory);
    return 0;
}

// Module vtable (module supported operations)
static struct fuse_operations hpcfs_vtable =
{
    .getattr  = hpcfs_getattr,
    .readlink = hpcfs_readlink,
    .opendir  = hpcfs_opendir,
    .readdir  = hpcfs_readdir
};

// Main module entry
int main(int argc, char **argv)
{
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    char             *configuration = NULL;
    int              status, help = 0, version = 0;

    while (*argv)
    {
        if (! strcasecmp(*argv, "-h") || ! strcasecmp(*argv, "--help"))
        {
            help = 1;
        }
        if (! strcmp(*argv, "-V") || ! strcasecmp(*argv, "--version"))
        {
            version = 1;
        }
        if (! strcasecmp(*argv, "-o") && *(argv + 1) && ! strncasecmp(*(argv + 1), "hpcfsconfig=", 12))
        {
            argv ++;
            configuration = strdup(*argv + 12);
        }
        else
        {
            fuse_opt_add_arg(&args, *argv);
        }
        argv ++;
    }
    if (! configuration)
    {
        configuration = strdup("/etc/hpcfs.conf");
    }
    if ((status = hpcfs_parse_configuration(configuration)) && ! (help || version))
    {
        return status;
    }
    if (! hpcfs_cache_root && ! (help || version))
    {
        fprintf(stderr, "hpcfs: missing or invalid CacheRoot directive in configuration file\n");
        return 1;
    }
    status = fuse_main(args.argc, args.argv, &hpcfs_vtable, NULL);
    if (help)
    {
        fprintf(stderr, "\n[hpcfs]\n    -o hpcfsconfig=FILE     set module configuration file (mandatory)\n");
    }
    return status;
}
