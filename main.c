#include <pcap.h>
#include <time.h>
#include <winsock.h>
#include <stdio.h>

#ifdef _WIN32
#include <tchar.h>
static int count;
char buf[65535];
BOOL LoadNpcapDlls()
{
    _TCHAR npcap_dir[512];
    UINT len;
    len = GetSystemDirectory(npcap_dir, 480);
    if (!len)
    {
        fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
        return FALSE;
    }
    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
    if (SetDllDirectory(npcap_dir) == 0)
    {
        fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
        return FALSE;
    }
    return TRUE;
}
#endif

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/* 用于测量捕获 1000 个数据包的时间 */
clock_t start_time, end_time;

int main()
{
    count = 0;
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i = 0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask;
    char packet_filter[] = "udp";
    struct bpf_program fcode;

#ifdef _WIN32
    /* Load Npcap and its functions. */
    if (!LoadNpcapDlls())
    {
        fprintf(stderr, "Couldn't load Npcap\n");
        exit(1);
    }
#endif

    /* Retrieve the device list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* Print the list */
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):", i);
    scanf("%d", &inum);

    /* Check if the user specified a valid adapter */
    if (inum < 1 || inum > i)
    {
        printf("\nAdapter number out of range.\n");

        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Jump to the selected adapter */
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++)
        ;

    /* Open the adapter */
    if ((adhandle = pcap_open_live(d->name,    // name of the device
                                   65536,      // portion of the packet to capture.
                                               // 65536 grants that the whole packet will be captured on all the MACs.
                                   1,          // promiscuous mode (nonzero means promiscuous)
                                   1000,       // read timeout
                                   errbuf      // error buffer
                                   )) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter: %s\n", errbuf);
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    int buffer_size = 1000000 * 10; // 设置 10MB 缓冲区
    if (pcap_set_buffer_size(adhandle, buffer_size) < 0)
    {
        fprintf(stderr, "Error setting buffer size\n");
    }

    /* Check the link layer. We support only Ethernet for simplicity. */
    if (pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    if (d->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask = 0xffffff;

    // compile the filter
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
    {
        fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    // set the filter
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        fprintf(stderr, "\nError setting the filter.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nListening on %s...\n", d->description);

    /* Free the device list */
    pcap_freealldevs(alldevs);

    /* 开始计时 */
    start_time = clock();

    int size = 100000;
    /* 开始捕获数据包，限制为 1000 个 */
    pcap_loop(adhandle, size, packet_handler, NULL);

    /* 结束计时 */
    end_time = clock();

    /* 计算并输出捕获 1000 个数据包所需时间 */
    double elapsed_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    printf("Captured %d packets in %.2f seconds. #count=%d\n", size, elapsed_time, count);

    return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    // printf("#%d\n", count++);
    // count++;
    memcpy(buf, pkt_data, header->caplen);
    
}
