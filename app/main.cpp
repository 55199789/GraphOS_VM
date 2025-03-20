#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#include <array>
#include <iostream>
#include <cstring>
#include <fstream>
#include <stdexcept>

using namespace std;
#define MAX_PATH FILENAME_MAX

#include "RAMStoreEnclaveInterface.h"
#include "Common.h"
#include "GraphNode.h"
#include "Node.h"
/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

// This sample is confined to the communication between a SGX client platform
// and an ISV Application Server. 


#include <chrono>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif


int main(int argc, char *argv[]) {
    (void) (argc);
    (void) (argv);

    /* My Codes */
    int size = 0;
    string filename = "";
    string alg = "";
    if (argc > 1) {
        filename = string(argv[1]);
        alg = string(argv[2]);
    } else {
        filename = "datasets/V13E-256.in";
        alg = "OBLIVIOUS-BFS";
    }
    std::ifstream inFile(filename);
    size = std::count(std::istreambuf_iterator<char>(inFile), std::istreambuf_iterator<char>(), '\n');

    std::ifstream infile((filename).c_str());


    map<Bid, string> pairs;
    vector<block> ciphertexts;
    vector<GraphNode> edgeList;

    int node_numebr = 0;
    int testEdgesrc, testEdgeDst;

    for (int i = 0; i < size; i++) {
        int src, dst, weight;
        infile >> src >> dst >> weight;
        GraphNode node;
        node.src_id = src;
        node.dst_id = dst;
        node.weight = weight;
        if (src == dst) {
            node_numebr++;
        } else {
            if (node.weight == 0) {
                node.weight = 1;
            }
            edgeList.push_back(node);
        }
    }
    int encryptionSize = sizeof (GraphNode); 
    int maxPad = (int) pow(2, ceil(log2(edgeList.size())));
    char* edges = new char[maxPad * encryptionSize];
    long long maxSize = node_numebr;
    int depth = (int) (ceil(log2(maxSize)) - 1) + 1;
    int maxOfRandom = (long long) (pow(2, depth));
    unsigned long long bucketCount = maxOfRandom * 2 - 1;
    unsigned long long blockSize = sizeof (Node); // B  
    size_t blockCount = (size_t) (Z * bucketCount);

    int edgeNumner = edgeList.size();
    edgeList.clear();

    for (int i = 1; i <= node_numebr; i++) {
        string omapKey = "?" + to_string(i);
        std::array< uint8_t, ID_SIZE > keyArray;
        keyArray.fill(0);
        std::copy(omapKey.begin(), omapKey.end(), std::begin(keyArray));
        std::array<byte_t, ID_SIZE> id;
        std::memcpy(id.data(), (const char*) keyArray.data(), ID_SIZE);
        Bid inputBid(id);
        pairs[inputBid] = "0-0";
    }

    setupMode = true;
    unsigned long long storeBlockSize = (size_t)Z *(size_t) (blockSize);

    ocall_setup_ramStore(blockCount, storeBlockSize);
    ocall_nwrite_raw_ramStore(&ciphertexts);
    Utilities::startTimer(1);

    int op = -1;
    if (alg == "OBLIVIOUS-SSSP-OBLIVM") {
        op = 3;
    } else if (alg == "OBLIVIOUS-MST") {
        op = 2;
    } else if (alg == "OBLIVIOUS-BFS") {
        op = 1;
    }

   

    auto timer = Utilities::stopTimer(1);
    cout << "Setup Time:" << timer << " Microseconds" << endl;

    Utilities::startTimer(5);
    if (alg == "SSSP-OBLIVM" || alg == "sssp-oblivm") {
        cout << "Running SSSP-OBLIVM" << endl;
        ecall_oblivm_single_source_shortest_path(1);
    } else if (alg == "OBLIVIOUS-SSSP-OBLIVM" || alg == "oblivious-sssp-oblivm") {
        cout << "Running Oblivious SSSP-OBLIVM" << endl;
        ecall_oblivious_oblivm_single_source_shortest_path(1);
    } else {
        cout << "unknown algorithm" << endl;
    }
    auto exectime = Utilities::stopTimer(5);
    cout << "Time:" << exectime << " Microseconds" << endl;




    return 0;
}

