#pragma once 
#include "ORAMEnclaveInterface.h"
#include "Common.h"

void ecall_setup_with_small_memory(int eSize, long long vSize, char **edgeList, int op);
void ecall_oblivious_oblivm_single_source_shortest_path(int src);
void ecall_oblivm_single_source_shortest_path(int src);