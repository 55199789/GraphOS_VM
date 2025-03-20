#include "Enclave.h"
#include <assert.h>
#include "Enclave_t.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "string.h"
#include <algorithm>
#include <math.h>
#include "OMAP/OMAP.h"
#include "OMAP/AES.hpp"
#include "GraphNode.h"

// This is the public EC key of the SP. The corresponding private EC key is
// used by the SP to sign data used in the remote attestation SIGMA protocol
// to sign channel binding data in MSG2. A successful verification of the
// signature confirms the identity of the SP to the ISV app in remote
// attestation secure channel binding. The public EC key should be hardcoded in
// the enclave or delivered in a trustworthy manner. The use of a spoofed public
// EC key in the remote attestation with secure channel binding session may lead
// to a security compromise. Every different SP the enlcave communicates to
// must have a unique SP public key. Delivery of the SP public key is
// determined by the ISV. The TKE SIGMA protocl expects an Elliptical Curve key
// based on NIST P-256
static const sgx_ec256_public_t g_sp_pub_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }

};

// Used to store the secret passed by the SP in the sample code. The
// size is forced to be 8 bytes. Expected value is
// 0x01,0x02,0x03,0x04,0x0x5,0x0x6,0x0x7
uint8_t g_secret[8] = {0};


#ifdef SUPPLIED_KEY_DERIVATION

#pragma message ("Supplied key derivation function is used.")

typedef struct _hash_buffer_t {
    uint8_t counter[4];
    sgx_ec256_dh_shared_t shared_secret;
    uint8_t algorithm_id[4];
} hash_buffer_t;

const char ID_U[] = "SGXRAENCLAVE";
const char ID_V[] = "SGXRASERVER";

// Derive two keys from shared key and key id.

bool derive_key(
        const sgx_ec256_dh_shared_t *p_shared_key,
        uint8_t key_id,
        sgx_ec_key_128bit_t *first_derived_key,
        sgx_ec_key_128bit_t *second_derived_key) {
    sgx_status_t sgx_ret = SGX_SUCCESS;
    hash_buffer_t hash_buffer;
    sgx_sha_state_handle_t sha_context;
    sgx_sha256_hash_t key_material;

    memset(&hash_buffer, 0, sizeof (hash_buffer_t));
    /* counter in big endian  */
    hash_buffer.counter[3] = key_id;

    /*convert from little endian to big endian */
    for (size_t i = 0; i < sizeof (sgx_ec256_dh_shared_t); i++) {
        hash_buffer.shared_secret.s[i] = p_shared_key->s[sizeof (p_shared_key->s) - 1 - i];
    }

    sgx_ret = sgx_sha256_init(&sha_context);
    if (sgx_ret != SGX_SUCCESS) {
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*) & hash_buffer, sizeof (hash_buffer_t), sha_context);
    if (sgx_ret != SGX_SUCCESS) {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*) & ID_U, sizeof (ID_U), sha_context);
    if (sgx_ret != SGX_SUCCESS) {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*) & ID_V, sizeof (ID_V), sha_context);
    if (sgx_ret != SGX_SUCCESS) {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_get_hash(sha_context, &key_material);
    if (sgx_ret != SGX_SUCCESS) {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_close(sha_context);

    assert(sizeof (sgx_ec_key_128bit_t)* 2 == sizeof (sgx_sha256_hash_t));
    memcpy(first_derived_key, &key_material, sizeof (sgx_ec_key_128bit_t));
    memcpy(second_derived_key, (uint8_t*) & key_material + sizeof (sgx_ec_key_128bit_t), sizeof (sgx_ec_key_128bit_t));

    // memset here can be optimized away by compiler, so please use memset_s on
    // windows for production code and similar functions on other OSes.
    memset(&key_material, 0, sizeof (sgx_sha256_hash_t));

    return true;
}

//isv defined key derivation function id
#define ISV_KDF_ID 2

typedef enum _derive_key_type_t {
    DERIVE_KEY_SMK_SK = 0,
    DERIVE_KEY_MK_VK,
} derive_key_type_t;

sgx_status_t key_derivation(const sgx_ec256_dh_shared_t* shared_key,
        uint16_t kdf_id,
        sgx_ec_key_128bit_t* smk_key,
        sgx_ec_key_128bit_t* sk_key,
        sgx_ec_key_128bit_t* mk_key,
        sgx_ec_key_128bit_t* vk_key) {
    bool derive_ret = false;

    if (NULL == shared_key) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (ISV_KDF_ID != kdf_id) {
        //fprintf(stderr, "\nError, key derivation id mismatch in [%s].", __FUNCTION__);
        return SGX_ERROR_KDF_MISMATCH;
    }

    derive_ret = derive_key(shared_key, DERIVE_KEY_SMK_SK,
            smk_key, sk_key);
    if (derive_ret != true) {
        //fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
        return SGX_ERROR_UNEXPECTED;
    }

    derive_ret = derive_key(shared_key, DERIVE_KEY_MK_VK,
            mk_key, vk_key);
    if (derive_ret != true) {
        //fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
        return SGX_ERROR_UNEXPECTED;
    }
    return SGX_SUCCESS;
}
#else
#pragma message ("Default key derivation function is used.")
#endif

// This ecall is a wrapper of sgx_ra_init to create the trusted
// KE exchange key context needed for the remote attestation
// SIGMA API's. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
// @param b_pse Indicates whether the ISV app is using the
//              platform services.
// @param p_context Pointer to the location where the returned
//                  key context is to be copied.
//
// @return Any error return from the create PSE session if b_pse
//         is true.
// @return Any error returned from the trusted key exchange API
//         for creating a key context.

sgx_status_t enclave_init_ra(
        int b_pse,
        sgx_ra_context_t *p_context) {
    // isv enclave call to trusted key exchange library.
    sgx_status_t ret;
    if (b_pse) {
        int busy_retry_times = 2;
        do {
            ret = sgx_create_pse_session();
        } while (ret == SGX_ERROR_BUSY && busy_retry_times--);
        if (ret != SGX_SUCCESS)
            return ret;
    }
#ifdef SUPPLIED_KEY_DERIVATION
    ret = sgx_ra_init_ex(&g_sp_pub_key, b_pse, key_derivation, p_context);
#else
    ret = sgx_ra_init(&g_sp_pub_key, b_pse, p_context);
#endif
    if (b_pse) {
        sgx_close_pse_session();
        return ret;
    }
    return ret;
}


// Closes the tKE key context used during the SIGMA key
// exchange.
//
// @param context The trusted KE library key context.
//
// @return Return value from the key context close API

sgx_status_t SGXAPI enclave_ra_close(
        sgx_ra_context_t context) {
    sgx_status_t ret;
    ret = sgx_ra_close(context);
    return ret;
}


// Verify the mac sent in att_result_msg from the SP using the
// MK key. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
//
// @param context The trusted KE library key context.
// @param p_message Pointer to the message used to produce MAC
// @param message_size Size in bytes of the message.
// @param p_mac Pointer to the MAC to compare to.
// @param mac_size Size in bytes of the MAC
//
// @return SGX_ERROR_INVALID_PARAMETER - MAC size is incorrect.
// @return Any error produced by tKE  API to get SK key.
// @return Any error produced by the AESCMAC function.
// @return SGX_ERROR_MAC_MISMATCH - MAC compare fails.

sgx_status_t verify_att_result_mac(sgx_ra_context_t context,
        uint8_t* p_message,
        size_t message_size,
        uint8_t* p_mac,
        size_t mac_size) {
    sgx_status_t ret;
    sgx_ec_key_128bit_t mk_key;

    if (mac_size != sizeof (sgx_mac_t)) {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }
    if (message_size > UINT32_MAX) {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }

    do {
        uint8_t mac[SGX_CMAC_MAC_SIZE] = {0};

        ret = sgx_ra_get_keys(context, SGX_RA_KEY_MK, &mk_key);
        if (SGX_SUCCESS != ret) {
            break;
        }
        ret = sgx_rijndael128_cmac_msg(&mk_key,
                p_message,
                (uint32_t) message_size,
                &mac);
        if (SGX_SUCCESS != ret) {
            break;
        }
        if (0 == consttime_memequal(p_mac, mac, sizeof (mac))) {
            ret = SGX_ERROR_MAC_MISMATCH;
            break;
        }

    } while (0);

    return ret;
}


// Generate a secret information for the SP encrypted with SK.
// Input pointers aren't checked since the trusted stubs copy
// them into EPC memory.
//
// @param context The trusted KE library key context.
// @param p_secret Message containing the secret.
// @param secret_size Size in bytes of the secret message.
// @param p_gcm_mac The pointer the the AESGCM MAC for the
//                 message.
//
// @return SGX_ERROR_INVALID_PARAMETER - secret size if
//         incorrect.
// @return Any error produced by tKE  API to get SK key.
// @return Any error produced by the AESGCM function.
// @return SGX_ERROR_UNEXPECTED - the secret doesn't match the
//         expected value.

sgx_status_t put_secret_data(
        sgx_ra_context_t context,
        uint8_t *p_secret,
        uint32_t secret_size,
        uint8_t *p_gcm_mac) {
    sgx_status_t ret = SGX_SUCCESS;
    sgx_ec_key_128bit_t sk_key;

    do {
        if (secret_size != 8) {
            ret = SGX_ERROR_INVALID_PARAMETER;
            break;
        }

        ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
        if (SGX_SUCCESS != ret) {
            break;
        }

        uint8_t aes_gcm_iv[12] = {0};
        ret = sgx_rijndael128GCM_decrypt(&sk_key,
                p_secret,
                secret_size,
                &g_secret[0],
                &aes_gcm_iv[0],
                12,
                NULL,
                0,
                (const sgx_aes_gcm_128bit_tag_t *)
                (p_gcm_mac));

        uint32_t i;
        bool secret_match = true;
        for (i = 0; i < secret_size; i++) {
            if (g_secret[i] != i) {
                secret_match = false;
            }
        }

        if (!secret_match) {
            ret = SGX_ERROR_UNEXPECTED;
        }

        // Once the server has the shared secret, it should be sealed to
        // persistent storage for future use. This will prevents having to
        // perform remote attestation until the secret goes stale. Once the
        // enclave is created again, the secret can be unsealed.
    } while (0);
    return ret;
}

//int PLAINTEXT_LENGTH = sizeof (GraphNode);
//int PLAINTEXT_LENGTH2 = sizeof (pair<int, int>);
//int CIPHER_LENGTH = SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + PLAINTEXT_LENGTH;
//int CIPHER_LENGTH2 = SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + PLAINTEXT_LENGTH2;


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

//SSSP with oblivm version min heap

void ecall_oblivm_single_source_shortest_path(int src) {
    ecall_setup_oheap(edgeNumber);

    ocall_start_timer(34);
    for (int i = 1; i <= vertexNumber; i++) {
        writeOMAP("/" + to_string(i), to_string(MY_MAX));
    }

    writeOMAP("/" + to_string(src), "0");
    ecall_set_new_minheap_node(src - 1, 0);

    bool innerloop = false;
    string dstStr, omapKey;
    int u = -1, cnt = 1, distu = -1, curDistU = -1;

    for (int i = 0; i < (2 * vertexNumber + edgeNumber); i++) {
        if (i % 10 == 0) {
            printf("%d/%d\n", i, vertexNumber + edgeNumber);
        }
        if (innerloop == false) {
            u = -1;
            distu = -1;
            ecall_extract_min_id(&u, &distu);
            if (u == -1) {
                u = u;
                curDistU = -2;
            } else {
                u++;
                string readData = readOMAP("/" + to_string(u));
                curDistU = stoi(readData);
            }

            if (curDistU == distu) {
                cnt = 1;
                omapKey = "$" + to_string(u) + "-" + to_string(cnt);
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
        } else {
            auto parts = splitData(dstStr, "-");
            int v = stoi(parts[0]);
            int weight = stoi(parts[1]);
            int distU = curDistU;
            int distV = stoi(readOMAP("/" + to_string(v)));

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

    ocall_start_timer(34);


    readWriteOMAP("/" + to_string(src), "0");
    ecall_set_new_minheap_node(src - 1, 0);

    bool innerloop = false;
    string dstStr, omapKey;
    int u = -1, cnt = 1, distu = -1, distv = -1, v = -1, curDistU = -1, weight = -1;
    string mapKey = "", mapValue = "", tmp = "";

    for (int i = 0; i < (2 * vertexNumber + edgeNumber); i++) {
        if (i % 10 == 0) {
            printf("%d/%d\n", i, 2 * vertexNumber + edgeNumber);
        }
        bool check = Node::CTeq(dstStr.length(), 0) && !innerloop;
        dstStr = CTString("0-0", dstStr, check);
        auto parts = splitData(dstStr, "-");
        v = Node::conditional_select(stoi(parts[0]), v, innerloop);
        //        v = innerloop ? stoi(parts[0]) : v;
        weight = Node::conditional_select(stoi(parts[1]), weight, innerloop);
        //        weight = innerloop ? stoi(parts[1]) : weight;       //TODO
        distu = Node::conditional_select(curDistU, -1, innerloop);
        //        distu = innerloop ? curDistU : -1;

        mapKey = CTString(to_string(v), "0", innerloop);
        //        mapKey = innerloop ? to_string(v) : "-";
        u = Node::conditional_select(u, -1, innerloop);
        //        u = innerloop ? u : -1;
        tmp = readOMAP("/" + to_string(v));

        check = Node::CTeq(tmp.length(), 0) && !innerloop;
        tmp = CTString("0-0", tmp, check);
        distv = Node::conditional_select(stoi(tmp), distv, innerloop);
        //        distv = innerloop ? stoi(tmp) : distv;
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
        curDistU = Node::conditional_select(stoi(tmp), curDistU, !innerloop && !Node::CTeq(u, -1));
        //        curDistU = ((innerloop == false) && u != -1) ? stoi(tmp) : curDistU;
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