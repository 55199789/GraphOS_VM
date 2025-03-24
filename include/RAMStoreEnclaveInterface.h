#pragma once
#include "RAMStore.hpp"
#include "Utilities.h"
#include <assert.h>
#include <cstring>
extern bool setupMode;
void ocall_setup_heapStore(size_t num, int size);

void ocall_setup_ramStore(size_t num, int size);

void ocall_nwrite_ramStore(size_t blockCount, long long *indexes, const char *blk, size_t len);

void ocall_nwrite_heapStore(size_t blockCount, long long *indexes, const char *blk, size_t len);

void ocall_write_rawRamStore(long long index, const char *blk, size_t len);

void ocall_write_prfRamStore(long long index, const char *blk, size_t len);

void ocall_nwrite_rawRamStore(size_t blockCount, long long *indexes, const char *blk, size_t len);

void ocall_nwrite_ramStore_by_client(vector<long long> *indexes, vector<block> *ciphertexts);

void ocall_nwrite_raw_ramStore(vector<block> *ciphertexts);

void ocall_finish_setup();

void ocall_begin_setup();

void ocall_nwrite_rawRamStore_for_graph(size_t blockCount, long long *indexes, const char *blk, size_t len);

size_t ocall_nread_ramStore(size_t blockCount, long long *indexes, char *blk, size_t len);

size_t ocall_nread_heapStore(size_t blockCount, long long *indexes, char *blk, size_t len);

size_t ocall_read_rawRamStore(size_t index, char *blk, size_t len);

size_t ocall_read_prfRamStore(size_t index, char *blk, size_t len);

size_t ocall_nread_rawRamStore(size_t blockCount, size_t begin, char *blk, size_t len);

size_t ocall_nread_prf(size_t blockCount, size_t begin, char *blk, size_t len);

void ocall_initialize_ramStore(long long begin, long long end, const char *blk, size_t len);

void ocall_initialize_heapStore(long long begin, long long end, const char *blk, size_t len);

void ocall_write_ramStore(long long index, const char *blk, size_t len);

void ocall_write_heapStore(long long index, const char *blk, size_t len);

void ocall_nwrite_prf(size_t blockCount, long long *indexes, const char *blk, size_t len);