#include "OMAP.h"
using namespace std;

OMAP::OMAP(int maxSize, bool isEmptyOMAP) {
    treeHandler = new AVLTree(maxSize, isEmptyOMAP);
    rootKey = 0;
    std::cout << "init 1, rootKey: " << rootKey.getValue() << std::endl;
}

OMAP::OMAP(int maxSize, map<Bid, string>* pairs, map<unsigned long long, unsigned long long>* permutation) {
    treeHandler = new AVLTree(maxSize, rootKey, rootPos, pairs, permutation);
    std::cout << "init 2, rootKey: " << rootKey.getValue() << std::endl;
}

OMAP::OMAP(int maxSize, Bid rootBid, long long rootPos) {
    treeHandler = new AVLTree(maxSize, false);
    this->rootKey = rootBid;
    this->rootPos = rootPos;
    std::cout << "init 3, rootKey: " << rootKey.getValue() << std::endl;
}

OMAP::OMAP(int maxSize, long long initialSize) {
    treeHandler = new AVLTree(maxSize, initialSize, this->rootKey, this->rootPos);
    std::cout << "init 4, rootKey: " << rootKey.getValue() << ", rootPos: " << this->rootPos << std::endl;
}

OMAP::~OMAP() {

}

string OMAP::find(Bid omapKey) {
    if (rootKey == 0) {
        return "";
    }
    treeHandler->startOperation(false);
    Node* node = new Node();
    node->key = rootKey;
    node->pos = rootPos;
    string res = treeHandler->search(node, omapKey);
    rootPos = node->pos;
    delete node;
    treeHandler->finishOperation();
    return res;
}

void OMAP::insert(Bid omapKey, string value) {
    treeHandler->totheight = 0;
    int height;
    treeHandler->startOperation(false);
    std::cout << "rootKey: " << rootKey.getValue() << std::endl;
    if (rootKey == 0) {
        rootKey = treeHandler->insert(0, rootPos, omapKey, value, height, omapKey, false);
    } else {
        rootKey = treeHandler->insert(rootKey, rootPos, omapKey, value, height, omapKey, false);
    }
    std::cout << "rootKey: " << rootKey.getValue() << std::endl;
    treeHandler->finishOperation();
}

void OMAP::printTree() {
    Node* node = new Node();
    node->key = rootKey;
    node->pos = rootPos;
    treeHandler->printTree(node, 0);
}

/**
 * This function is used for batch insert which is used at the end of setup phase.
 */
void OMAP::batchInsert(map<Bid, string> pairs) {
    treeHandler->startOperation(true);
    int cnt = 0, height;
    for (auto pair : pairs) {
        cnt++;
        if (rootKey == 0) {
            rootKey = treeHandler->insert(0, rootPos, pair.first, pair.second, height, 0, false);
        } else {
            rootKey = treeHandler->insert(rootKey, rootPos, pair.first, pair.second, height, 0, false);
        }
    }
    treeHandler->finishOperation();
}

/**
 * This function is used for batch search which is used in the real search procedure
 */
//vector<string> OMAP::batchSearch(vector<Bid> keys) {
//    vector<string> result;
//    treeHandler->startOperation(false);
//    Node* node = new Node();
//    node->key = rootKey;
//    node->pos = rootPos;
//
//    vector<Node*> resNodes;
//    treeHandler->batchSearch(node, keys, &resNodes);
//    for (Node* n : resNodes) {
//        string res;
//        if (n != NULL) {
//            res.assign(n->value.begin(), n->value.end());
//            result.push_back(res);
//        } else {
//            result.push_back("");
//        }
//    }
//    treeHandler->finishOperation();
//    return result;
//}

string OMAP::setSpt(Bid mapKey) {
    if (rootKey == 0) {
        return "";
    }
    treeHandler->startOperation(false);
    Node* node = new Node();
    node->key = rootKey;
    node->pos = rootPos;
    string res = "";
    treeHandler->searchAndIncrement(node, mapKey, res, false);
    rootPos = node->pos;
    delete node;
    treeHandler->finishOperation();
    return res;
}

string OMAP::incPart(Bid mapKey, bool isFirstPart) {
    if (rootKey == 0) {
        return "";
    }
    treeHandler->startOperation(false);
    Node* node = new Node();
    node->key = rootKey;
    node->pos = rootPos;
    string res = "";
    treeHandler->searchAndIncrement(node, mapKey, res, isFirstPart);
    rootPos = node->pos;
    delete node;
    treeHandler->finishOperation();
    return res;
}

string OMAP::readAndSetDist(Bid mapKey, string newValue) {
    if (rootKey == 0) {
        return "";
    }
    treeHandler->startOperation(false);
    Node* node = new Node();
    node->key = rootKey;
    node->pos = rootPos;
    string res = "";
    treeHandler->readAndSetDist(node, mapKey, res, newValue);
    rootPos = node->pos;
    delete node;
    treeHandler->finishOperation();
    return res;
}

string OMAP::searchInsert(Bid mapKey, string newValue) {
    if (rootKey == 0) {
        return "";
    }
    treeHandler->startOperation(false);
    Node* node = new Node();
    node->key = rootKey;
    node->pos = rootPos;
    string res = "";
    treeHandler->searchInsert(node, mapKey, res, newValue);
    rootPos = node->pos;
    delete node;
    treeHandler->finishOperation();
    return res;
}

void OMAP::setupInsert(map<Bid, string> pairs) {
    treeHandler->setupInsert(rootKey, rootPos, pairs);
}

string OMAP::atomicFind(Bid omapKey) {
    if (rootKey == 0) {
        return "";
    }
    Node* node = new Node();
    node->key = rootKey;
    node->pos = rootPos;
    string res = treeHandler->search(node, omapKey);
    rootPos = node->pos;
    delete node;
    return res;
}

void OMAP::atomicInsert(Bid omapKey, string value) {
    //    treeHandler->totheight = 0;
    int height;
    if (rootKey == 0) {
        rootKey = treeHandler->insert(0, rootPos, omapKey, value, height, omapKey, false);
    } else {
        rootKey = treeHandler->insert(rootKey, rootPos, omapKey, value, height, omapKey, false);
    }
}

string OMAP::atomicReadAndSetDist(Bid mapKey, string newValue) {
    if (rootKey == 0) {
        return "";
    }
    Node* node = new Node();
    node->key = rootKey;
    node->pos = rootPos;
    string res = "";
    treeHandler->readAndSetDist(node, mapKey, res, newValue);
    rootPos = node->pos;
    delete node;
    return res;
}