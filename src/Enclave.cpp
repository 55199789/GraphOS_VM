#include "Enclave.h"
#include <assert.h>
#include "string.h"
#include <algorithm>
#include <math.h>
#include "OMAP.h"
#include "RAMStoreEnclaveInterface.h"
#include "GraphNode.h"

#define MY_MAX 9999999
#define KV_MAX_SIZE 8192

void check_memory4(string text) {
    unsigned int required = 0x4f00000; // adapt to native uint
    char *mem = NULL;
    while (mem == NULL) {
        mem = (char*) malloc(required);
        if ((required -= 8) < 0xFFF) {
            if (mem) free(mem);
            printf("Cannot allocate enough memory\n");
            return;
        }
    }

    free(mem);
    mem = (char*) malloc(required);
    if (mem == NULL) {
        printf("Cannot enough allocate memory\n");
        return;
    }
    printf("%s = %d\n", text.c_str(), required);
    free(mem);
}

int vertexNumber = 0;
int edgeNumber = 0;
int maximumPad = 0;
map<Bid, string> finalPairs;
long long KV_index = 0;
unsigned long long edgeBlockSize = sizeof (GraphNode);
unsigned long long edgeClenSize = edgeBlockSize;
unsigned long long edgePlaintextSize = (edgeBlockSize);
unsigned long long edgeStoreSingleBlockSize = edgeClenSize;
unsigned long long blockSize = sizeof (Node);
unsigned long long clen_size = blockSize;
unsigned long long plaintext_size = (blockSize);
unsigned long long storeSingleBlockSize = clen_size;
unsigned long long pairBlockSize = sizeof (pair<int, int>);
unsigned long long pairClenSize = pairBlockSize;
unsigned long long pairPlaintextSize = (pairBlockSize);
unsigned long long pairStoreSingleBlockSize = pairClenSize;

string readOMAP(string omapKey) {
    std::array< uint8_t, ID_SIZE > keyArray;
    keyArray.fill(0);
    std::copy(omapKey.begin(), omapKey.end(), std::begin(keyArray));

    char* value = new char[16];
    ecall_read_node((const char*) keyArray.data(), value);
    string result(value);
    delete value;
    return result;
}

void writeOMAP(string omapKey, string omapValue) {
    std::array< uint8_t, ID_SIZE > keyArray;
    keyArray.fill(0);
    std::copy(omapKey.begin(), omapKey.end(), std::begin(keyArray));

    std::array< uint8_t, 16 > valueArray;
    valueArray.fill(0);
    std::copy(omapValue.begin(), omapValue.end(), std::begin(valueArray));

    ecall_write_node((const char*) keyArray.data(), (const char*) valueArray.data());
}

string readWriteOMAP(string omapKey, string omapValue) {
    std::array< uint8_t, ID_SIZE > keyArray;
    keyArray.fill(0);
    std::copy(omapKey.begin(), omapKey.end(), std::begin(keyArray));

    std::array< uint8_t, 16 > valueArray;
    valueArray.fill(0);
    std::copy(omapValue.begin(), omapValue.end(), std::begin(valueArray));
    char* oldvalue = new char[16];
    ecall_read_write_node((const char*) keyArray.data(), (const char*) valueArray.data(), oldvalue);
    string result(oldvalue);
    delete oldvalue;
    return result;
}


vector<string> splitData(const string& str, const string& delim) {
    vector<string> tokens = {"", ""};
    int pos = 0;
    for (int i = 0; i < str.length(); i++) {
        bool cond = Node::CTeq(str.at(i), '-');
        pos = Node::conditional_select(i, pos, cond);
    }
    string token = str.substr(0, pos);
    tokens[0] = token;
    int begin = Node::conditional_select(pos, pos + 1, Node::CTeq(Node::CTcmp(pos + 1, str.length()), 1));
    token = str.substr(begin, str.length());
    tokens[1] = token;
    return tokens;

    //    vector<string> tokens;
    //    size_t prev = 0, pos = 0;
    //    do {
    //        pos = str.find(delim, prev);
    //        if (pos == string::npos) pos = str.length();
    //        string token = str.substr(prev, pos - prev);
    //        if (!token.empty()) tokens.push_back(token);
    //        prev = pos + delim.length();
    //    } while (pos < str.length() && prev < str.length());
    //    return tokens;
}

string CTString(string a, string b, int choice) {
    unsigned int one = 1;
    string result = "";
    int maxSize = max(a.length(), b.length());
    for (int i = 0; i < maxSize; i++) {
        a += " ";
        b += " ";
    }
    for (int i = 0; i < maxSize; i++) {
        result += (~((unsigned int) choice - one) & a.at(i)) | ((unsigned int) (choice - one) & b.at(i));
    }
    result.erase(std::find_if(result.rbegin(), result.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), result.end());
    return result;
}

bool CTeq(string a, string b) {
    a.erase(std::find_if(a.rbegin(), a.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), a.end());
    b.erase(std::find_if(b.rbegin(), b.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), b.end());
    bool res = Node::CTeq((int) a.length(), (int) b.length());
    for (int i = 0; i < min((int) a.length(), (int) b.length()); i++) {
        res = Node::conditional_select(false, res, !Node::CTeq(a.at(i), b.at(i)));
    }
    return res;
}

void addKeyValuePair(string key, string value)
{
    if (key != "")
    {
        string omapKey = key;
        std::array<uint8_t, ID_SIZE> keyArray;
        keyArray.fill(0);
        std::copy(omapKey.begin(), omapKey.end(), std::begin(keyArray));
        std::array<byte_t, ID_SIZE> id;
        std::memcpy(id.data(), (const char *)keyArray.data(), ID_SIZE);
        Bid inputBid(id);
        finalPairs[inputBid] = value;
    }
    if (finalPairs.size() == KV_MAX_SIZE || ((key == "") && (value == "")))
    {
        char *tmp = new char[finalPairs.size() * storeSingleBlockSize];
        vector<long long> indexes;
        long long j = 0;
        for (auto pair : finalPairs)
        {
            Node *node = new Node();
            node->key = pair.first;
            node->index = 0;
            std::fill(node->value.begin(), node->value.end(), 0);
            std::copy(pair.second.begin(), pair.second.end(), node->value.begin());
            node->leftID = 0;
            node->leftPos = -1;
            node->rightPos = -1;
            node->rightID = 0;
            node->pos = 0;
            node->isDummy = false;
            node->height = 1; // new node is initially added at leaf

            indexes.push_back(KV_index);
            KV_index++;

            std::array<byte_t, sizeof(Node)> data;

            const byte_t *begin = reinterpret_cast<const byte_t *>(std::addressof(((*node))));
            const byte_t *end = begin + sizeof(Node);
            std::copy(begin, end, std::begin(data));

            block buffer(data.begin(), data.end());
            std::memcpy(tmp + j * buffer.size(), buffer.data(), storeSingleBlockSize);
            delete node;
            j++;
        }
        ocall_nwrite_rawRamStore_for_graph(finalPairs.size(), indexes.data(), (const char *)tmp, storeSingleBlockSize * finalPairs.size());
        delete tmp;
        finalPairs.clear();
    }
}

void ecall_pad_nodes(char **edgeList)
{
    int maxPad = (int)pow(2, ceil(log2(edgeNumber)));

    for (int i = edgeNumber; i < maxPad; i++)
    {
        GraphNode *node = new GraphNode();
        node->src_id = -1;
        node->dst_id = -1;
        node->weight = MY_MAX;

        block b = GraphNode::convertNodeToBlock(node);
        memcpy((uint8_t *)(*edgeList) + i * b.size(), b.data(), b.size());
        delete node;
    }
}

void ecall_setup_with_small_memory(int eSize, long long vSize, char **edgeList, int op = -1)
{
    size_t depth = (int)(ceil(log2(vSize)) - 1) + 1;
    long long maxOfRandom = (long long)(pow(2, depth));
    vertexNumber = vSize;
    edgeNumber = eSize;
    maximumPad = (int)pow(2, ceil(log2(edgeNumber)));
    long long KVNumber = 0;

    OMAP *omap = new OMAP(maxOfRandom, vSize);

    unsigned long long maxSize = (vertexNumber + edgeNumber) * 4;
    depth = (int)(ceil(log2(maxSize)) - 1) + 1;
    maxOfRandom = (long long)(pow(2, depth));
    unsigned long long bucketCount = maxOfRandom * 2 - 1;
    unsigned long long blockSize = sizeof(Node); // B
    unsigned long long blockCount = (size_t)(Z * bucketCount);
    ocall_finish_setup();
    ocall_setup_ramStore(blockCount, blockSize);
    ocall_begin_setup();

    for (int i = 0; i < eSize; i++)
    {
        if (i % 100 == 0)
            printf("%d/%d of edges processed\n", i, eSize);
        block buffer((*edgeList) + i * edgeStoreSingleBlockSize,
                     (*edgeList) + (i + 1) * edgeStoreSingleBlockSize);
        GraphNode *curEdge = GraphNode::convertBlockToNode(buffer);

        string srcBid = "?" + to_string(curEdge->src_id);
        std::array<byte_t, ID_SIZE> srcid;
        std::memcpy(srcid.data(), srcBid.data(), ID_SIZE);
        Bid srcInputBid(srcid);
        string srcCntStr = omap->incPart(srcInputBid, true);

        vector<string> parts = splitData(srcCntStr, "-");
        int outSrc = std::stoi(parts[0]) + 1;
        int inSrc = std::stoi(parts[1]);

        string dstBid = "?" + to_string(curEdge->dst_id);
        std::array<byte_t, ID_SIZE> dstid;
        std::memcpy(dstid.data(), dstBid.data(), ID_SIZE);
        Bid dstInputBid(dstid);
        string dstCntStr = omap->incPart(dstInputBid, false);

        parts = splitData(dstCntStr, "-");
        int outDst = std::stoi(parts[0]);
        int inDst = std::stoi(parts[1]) + 1;

        string src = to_string(curEdge->src_id);
        string dst = to_string(curEdge->dst_id);
        string weight = to_string(curEdge->weight);

        addKeyValuePair("$" + src + "-" + to_string(outSrc), dst + "-" + weight);
        addKeyValuePair("*" + dst + "-" + to_string(inDst), src + "-" + weight);
        addKeyValuePair("!" + src + "-" + dst, weight + "-" + to_string(outSrc) + "-" + to_string(inDst));
        KVNumber += 3;

        // SSSP SETUP
        if (op == 3)
        {
            addKeyValuePair("&" + to_string(i), "0-0");
            KVNumber++;
        }

        delete curEdge;
    }

    for (int i = 1; i <= vSize; i++)
    {
        if (i % 100 == 0)
        {
            printf("%d/%d of vertices processed\n", i, (int)vSize);
        }
        string bid = "?" + to_string(i);
        std::array<byte_t, ID_SIZE> id;
        std::memcpy(id.data(), bid.data(), ID_SIZE);
        Bid inputBid(id);
        string value = omap->find(inputBid);
        addKeyValuePair(bid, value);
        KVNumber++;

        // SSSP SETUP
        if (op == 1)
        {
            bid = "@" + to_string(i);
            value = "";
            addKeyValuePair(bid, value);
            KVNumber++;
            bid = "%" + to_string(i);
            value = "";
            addKeyValuePair(bid, value);
            KVNumber++;
        }
        else if (op == 2)
        {
            bid = "/" + to_string(i);
            value = to_string(i);
            addKeyValuePair(bid, value);
            KVNumber++;
        }
        else if (op == 3)
        {
            bid = "/" + to_string(i);
            value = to_string(MY_MAX);
            addKeyValuePair(bid, value);
            KVNumber++;
        }
    }

    if (op == 1)
    {
        string bid = "@" + to_string(0);
        string value = "";
        addKeyValuePair(bid, value);
        KVNumber++;
        bid = "%" + to_string(0);
        value = "";
        addKeyValuePair(bid, value);
        KVNumber++;
    }
    else if (op == 2 || op == 3)
    {
        string bid = "/" + to_string(0);
        string value = to_string(0);
        addKeyValuePair(bid, value);
        KVNumber++;
    }
    addKeyValuePair("", "");
    ecall_pad_nodes(edgeList);

    ocall_finish_setup();
    ecall_setup_omap_with_small_memory((vertexNumber + edgeNumber) * 4, KVNumber);
}

//SSSP with oblivm version min heap

void ecall_oblivm_single_source_shortest_path(int src) {
    ecall_setup_oheap(edgeNumber);

    std::cout << "set up oheap" << std::endl;

    ocall_start_timer(34);
    for (int i = 1; i <= vertexNumber; i++) {
        std::cout << "init dist of " << i << std::endl;
        writeOMAP("/" + to_string(i), to_string(MY_MAX));
    }

    writeOMAP("/" + to_string(src), "0");
    std::cout << "readWriteOMAP" << std::endl;
    ecall_set_new_minheap_node(src - 1, 0);
    std::cout << "Start with source node " << src << std::endl;

    bool innerloop = false;
    string dstStr, omapKey;
    int u = -1, cnt = 1, distu = -1, curDistU = -1;

    for (int i = 0; i < (2 * vertexNumber + edgeNumber); i++) {
        if (i % 1 == 0)
            printf("sssp: %d/%d\n", i, vertexNumber + edgeNumber);

        if (innerloop == false)
        {
            u = -1;
            distu = -1;
            ecall_extract_min_id(&u, &distu);
            std::cout << "u: " << u << ", distu: " << distu << std::endl;
            if (u == -1)
            {
                u = u;
                curDistU = -2;
            }
            else
            {
                u++;
                string readData = readOMAP("/" + to_string(u));
                curDistU = std::stoi(readData);
            }

            if (curDistU == distu) {
                cnt = 1;
                omapKey = "$" + to_string(u) + "-" + to_string(cnt);
                std::cout << "omapKey: " << omapKey << std::endl;
                dstStr = readOMAP(omapKey);
                if (dstStr != "") {
                    innerloop = true;
                } else {
                    innerloop = false;
                }
            } else {
                writeOMAP("/-", "");
            }
            writeOMAP("/-", "");
        }
        else
        {
            auto parts = splitData(dstStr, "-");
            int v = std::stoi(parts[0]);
            int weight = std::stoi(parts[1]);
            int distU = curDistU;
            int distV = std::stoi(readOMAP("/" + to_string(v)));

            if (weight + distU < distV) {
                writeOMAP("/" + to_string(v), to_string(distU + weight));
                ecall_set_new_minheap_node(v - 1, distU + weight);
            } else {
                writeOMAP("/-", "");
                ecall_dummy_heap_op();
            }
            cnt++;
            omapKey = "$" + to_string(u) + "-" + to_string(cnt);
            dstStr = readOMAP(omapKey);
            if (dstStr != "") {
                innerloop = true;
            } else {
                innerloop = false;
            }
        }
    }

    //    printf("Vertex   Distance from Source\n");
    //    for (int i = 1; i <= vertexNumber; i++) {
    //        printf("%d tt %s\n", i, readOMAP("/" + to_string(i)).c_str());
    //    }
}

void ecall_oblivious_oblivm_single_source_shortest_path(int src) {
    ecall_setup_oheap(edgeNumber);
    std::cout << "Setup oheap with " << edgeNumber << " edges" << std::endl;
    ocall_start_timer(34);

    readWriteOMAP("/" + to_string(src), "0");
    std::cout << "readWriteOMAP" << std::endl;
    ecall_set_new_minheap_node(src - 1, 0);
    std::cout << "Start with source node " << src << std::endl;

    bool innerloop = false;
    string dstStr, omapKey;
    int u = -1, cnt = 1, distu = -1, distv = -1, v = -1, curDistU = -1, weight = -1;
    string mapKey = "", mapValue = "", tmp = "";

    for (int i = 0; i < (2 * vertexNumber + edgeNumber); i++) {
        if (i % 1 == 0)
        {
            printf("odij: %d/%d\n", i, 2 * vertexNumber + edgeNumber);
        }
        bool check = Node::CTeq(dstStr.length(), 0) && !innerloop;
        dstStr = CTString("0-0", dstStr, check);
        auto parts = splitData(dstStr, "-");
        std::cout << "parts: " << parts[0] << ", " << parts[1] << std::endl;
        v = Node::conditional_select(std::stoi(parts[0]), v, innerloop);
        //        v = innerloop ? std::stoi(parts[0]) : v;
        weight = Node::conditional_select(std::stoi(parts[1]), weight, innerloop);
        //        weight = innerloop ? std::stoi(parts[1]) : weight;       //TODO
        distu = Node::conditional_select(curDistU, -1, innerloop);
        //        distu = innerloop ? curDistU : -1;
        std::cout << "v: " << v << ", weight: " << weight << ", distu: " << distu << std::endl;

        mapKey = CTString(to_string(v), "0", innerloop);
        //        mapKey = innerloop ? to_string(v) : "-";
        u = Node::conditional_select(u, -1, innerloop);
        //        u = innerloop ? u : -1;
        std::cout << "mapKey: " << mapKey << ", u: " << u << std::endl;
        tmp = readOMAP("/" + to_string(v));
        std::cout << "tmp: " << tmp << std::endl;

        check = Node::CTeq(tmp.length(), 0) && !innerloop;
        tmp = CTString("0-0", tmp, check);
        std::cout << "tmp: " << tmp << ", std::stoi(tmp): " << std::stoi(tmp) << std::endl;
        distv = Node::conditional_select(std::stoi(tmp), distv, innerloop);
        //        distv = innerloop ? std::stoi(tmp) : distv;
        mapValue = CTString(to_string(distu + weight), to_string(distv), innerloop && Node::CTeq(Node::CTcmp(distu + weight, distv), -1));
        //        mapValue = (innerloop && (distu + weight < distv)) ? to_string(distu + weight) : to_string(distv);
        readWriteOMAP("/" + mapKey, mapValue);

        int heapOp = 3;
        heapOp = Node::conditional_select(1, heapOp, !innerloop);
        heapOp = Node::conditional_select(2, heapOp, innerloop && Node::CTeq(Node::CTcmp(distu + weight, distv), -1));

        int heapV = u;
        int heapDist = distu;
        heapV = Node::conditional_select(v - 1, heapV, innerloop && Node::CTeq(Node::CTcmp(distu + weight, distv), -1));
        heapDist = Node::conditional_select(distu + weight, heapDist, innerloop && Node::CTeq(Node::CTcmp(distu + weight, distv), -1));

        ecall_execute_heap_operation(&heapV, &heapDist, heapOp);

        u = Node::conditional_select(heapV, u, !innerloop);
        distu = Node::conditional_select(heapDist, distu, !innerloop);

        //        if (innerloop == false) {
        //            ecall_extract_min_id(&u, &distu);
        //        } else if (innerloop && (distu + weight < distv)) {
        //            ecall_set_new_minheap_node(v - 1, distu + weight);
        //        } else {
        //            ecall_dummy_heap_op();
        //        }
        cnt = Node::conditional_select(cnt + 1, cnt, innerloop);
        //        cnt = innerloop ? cnt + 1 : cnt;
        u = Node::conditional_select(u + 1, u, !innerloop && !Node::CTeq(u, -1));
        mapKey = CTString(to_string(u), "0", !innerloop && !Node::CTeq(u, -1));
        //        mapKey = ((innerloop == false) && u != -1) ? to_string(++u) : "-";
        tmp = readOMAP("/" + mapKey);

        check = Node::CTeq(tmp.length(), 0) && (innerloop || Node::CTeq(u, -1));
        tmp = CTString("0-0", tmp, check);
        curDistU = Node::conditional_select(std::stoi(tmp), curDistU, !innerloop && !Node::CTeq(u, -1));
        //        curDistU = ((innerloop == false) && u != -1) ? std::stoi(tmp) : curDistU;
        curDistU = Node::conditional_select(-2, curDistU, !innerloop && Node::CTeq(u, -1));
        //        curDistU = ((innerloop == false) && u == -1) ? -2 : curDistU;
        cnt = Node::conditional_select(1, cnt, !innerloop && Node::CTeq(curDistU, distu));
        //        cnt = (innerloop == false && curDistU == distu) ? 1 : cnt;
        tmp = readOMAP("$" + to_string(u) + "-" + to_string(cnt));

        dstStr = CTString(tmp, dstStr, innerloop || Node::CTeq(curDistU, distu));
        //        dstStr = (innerloop || curDistU == distu) ? tmp : dstStr;

        innerloop = (innerloop && !Node::CTeq(dstStr.length(), 0)) || (!innerloop && Node::CTeq(curDistU, distu) && !Node::CTeq(dstStr.length(), 0));
        //        innerloop = (innerloop && dstStr != "") || (innerloop == false && curDistU == distu && dstStr != "") ? true : false;
    }

    printf("Vertex Distance from Source\n");
    for (int i = 1; i <= vertexNumber; i++) {
        printf("Destination:%d  Distance:%s\n", i, readOMAP("/" + to_string(i)).c_str());
    }
}