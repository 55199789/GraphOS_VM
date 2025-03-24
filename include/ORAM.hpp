#ifndef ORAM_H
#define ORAM_H

#include <random>
#include <vector>
#include <unordered_map>
#include <string>
#include <iostream>
#include <map>
#include <set>
#include "Bid.h"
#include "LocalRAMStore.hpp"
#include "Node.h"

using namespace std;

extern int BlockValueSize;
extern int BlockDummySize;

#define BATCH_SIZE 16384

class Cache {
public:
    vector<Node*> nodes;

    void preAllocate(int n) {
        nodes.reserve(n);
    }

    void insert(Node* node) {
        nodes.push_back(node);
    };

};

class ORAM {
private:
    std::random_device rd; 
    std::mt19937 gen;
    std::uniform_int_distribution<long long> dis;
    unsigned long long INF;
    unsigned int PERMANENT_STASH_SIZE;

    size_t blockSize;
    unordered_map<long long, Bucket> virtualStorage;
    Cache stash, incStash;
    unsigned long long currentLeaf;

    size_t plaintext_size;
    long long bucketCount;
    bool batchWrite = false;
    long long maxOfRandom;
    long long maxHeightOfAVLTree;
    bool useLocalRamStore = false;
    LocalRAMStore* localStore;
    int storeBlockSize;
    int stashCounter = 0;
    bool isIncomepleteRead = false;
    unsigned long long single_block_clen_size;
    unsigned long long storeSingleBlockSize;
    unsigned long long single_block_plaintext_size;

    unsigned long long RandomPath();
    long long GetNodeOnPath(long long leaf, int depth);

    void FetchPath(long long leaf);

    block SerialiseBucket(Bucket bucket);
    Bucket DeserialiseBucket(block buffer);

    void InitializeBuckets(long long strtindex, long long endindex, Bucket bucket);
    void ReadBuckets(vector<long long> indexes);
    void WriteBuckets(vector<long long> indexes, vector<Bucket> buckets);

    void WriteBucket(long long index, Bucket bucket);
    Node* getNode(int index);
    void setNode(int index, Node* node);

    void fetchBatch1(int beginIndex);
    void fetchBatch2(int beginIndex);

    void flushCache();
    vector<Node*> setupCache1;
    vector<Node*> setupCache2;
    unsigned long long currentBatchBegin1 = 0;
    unsigned long long currentBatchBegin2 = 0;
    bool isLeftBatchUpdated = false;
    unsigned long long totalNumberOfNodes;


    bool WasSerialised();
    Node* convertBlockToNode(block b);
    block convertNodeToBlock(Node* node);

    void beginOperation();
    vector<string> split(const string& str, const string& delim);

public:
    ORAM(long long maxSize, bool simulation, bool isEmptyMap);
    ORAM(long long maxSize, int nodesSize);
    void InitializeORAMBuckets();
    void InitializeBucketsOneByOne();
    void InitializeBucketsInBatch();


    ORAM(long long maxSize, vector<Node*>* nodes);
    ORAM(long long maxSize, vector<Node*>* nodes, map<unsigned long long, unsigned long long> permutation);
    void EvictBuckets();

    ~ORAM();
    double evicttime = 0;
    int evictcount = 0;
    unsigned long long nextDummyCounter;
    int readCnt = 0;
    int depth;
    int accessCounter = 0;
    bool shutdownEvictBucket = false;
    //-----------------------------------------------------------
    bool evictBuckets = false; //is used for AVL calls. It should be set the same as values in default values
    //-----------------------------------------------------------

    Node* ReadWrite(Bid bid, Node* node, unsigned long long lastLeaf, unsigned long long newLeaf, bool isRead, bool isDummy, bool isIncompleteRead);
    Node* ReadWriteTest(Bid bid, Node* node, unsigned long long lastLeaf, unsigned long long newLeaf, bool isRead, bool isDummy, bool isIncompleteRead);
    Node* ReadWrite(Bid bid, Node* node, unsigned long long lastLeaf, unsigned long long newLeaf, bool isRead, bool isDummy, std::array< byte_t, 16> value, bool overwrite, bool isIncompleteRead);
    Node* ReadWrite(Bid bid, unsigned long long lastLeaf, unsigned long long newLeaf, bool isDummy, unsigned long long newChildPos, Bid targetNode, std::array< byte_t, 16> newVec);
    Node* ReadWrite(Bid bid, unsigned long long lastLeaf, unsigned long long newLeaf, bool isDummy, unsigned long long newChildPos, Bid targetNode, string part, bool isFirstPart);
    Node* ReadWrite(Bid bid, unsigned long long lastLeaf, unsigned long long newLeaf, bool isDummy, unsigned long long newChildPos, Bid targetNode, bool isFirstPart);
    Node* ReadWrite(Bid bid, unsigned long long lastLeaf, unsigned long long newLeaf, bool isDummy, unsigned long long newChildPos, Bid targetNode);

    void start(bool batchWrite);
    void prepareForEvictionTest();
    void evict(bool evictBuckets);
    void setupInsert(vector<Node*>* nodes);
    void finilize(bool noDummyOp = false);
    bool profile = false;
};

#endif
