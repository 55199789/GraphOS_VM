#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string> 
#include "Utilities.h"


/* OCall functions */
#define ocall_print_string(str) printf("%s", str)
// void ocall_print_string(const char *str) {
//     /* Proxy/Bridge will check the length and null-terminate
//      * the input string to prevent buffer overflow.
//      */
//     printf("%s", str);
// }
#define ocall_start_timer(timerID) Utilities::startTimer(timerID)
// void ocall_start_timer(int timerID) {
//     Utilities::startTimer(timerID);
// }
#define ocall_stop_timer(timerID) Utilities::stopTimer(timerID)
// double ocall_stop_timer(int timerID) {
//     return Utilities::stopTimer(timerID);
// }
