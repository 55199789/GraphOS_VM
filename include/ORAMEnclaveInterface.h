#ifndef ORAMENCLAVEINTERFACE_H
#define ORAMENCLAVEINTERFACE_H

#include "OMAP.h"
//#include "OHeap.h"
#include "DOHEAP.hpp"
#include <string>
#include "Common.h"
#include <assert.h>

void ecall_setup_oram(int max_size);

void ecall_setup_omap_by_client(int max_size, const char *bid, long long rootPos);

void ecall_setup_omap_with_small_memory(int max_size, long long initialSize);
void ecall_setup_oheap(int maxSize);
void ecall_set_new_minheap_node(int newMinHeapNodeV, int newMinHeapNodeDist);

void ecall_execute_heap_operation(int *v, int *dist, int op);

void ecall_dummy_heap_op();

void ecall_extract_min_id(int *id, int *dist);
void ecall_read_node(const char *bid, char *value);

void ecall_read_and_set_node(const char *bid, char *value);

void ecall_read_write_node(const char *bid, const char *value, char *oldValue);

void ecall_write_node(const char *bid, const char *value);

void ecall_start_setup();

void ecall_end_setup();
void ecall_read_and_set_dist_node(const char *bid, const char *value, char *result);
double ecall_measure_oram_speed(int testSize);
void check_memory(string text);

double ecall_measure_omap_speed(int testSize);

double ecall_measure_eviction_speed(int testSize);

double ecall_measure_oram_setup_speed(int testSize);
double ecall_measure_omap_setup_speed(int testSize);
#endif /* ORAMENCLAVEINTERFACE_H */

