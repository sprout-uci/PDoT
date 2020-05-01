// #define MAX_CONCURRENT_THREADS 60
// #define QUERY_HANDLE_THREADS 30
#define MAX_CONCURRENT_THREADS 5
#define QUERY_HANDLE_THREADS 1

/* Queue for storing client info */
struct ClientQueueEntry {
    int connd;
    struct ClientQueueEntry* next;
};

struct ClientQueue {
    struct ClientQueueEntry* head;
    struct ClientQueueEntry* tail;
};
