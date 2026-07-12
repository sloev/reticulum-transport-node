#pragma once
// Minimal in-memory filesystem mock, just enough of the ESP32 LittleFS API
// surface (File::read/write/close/size/name/isDirectory/openNextFile,
// LittleFS.exists/mkdir/remove/open) for RetiLXMF.h to compile and run as a
// native host binary. Not wired into the main protocol/crypto test binary
// (see test/README.md's scoping note) -- only used by the separate
// LXMF compile/smoke check.
#include <map>
#include <vector>
#include <string>
#include <memory>
#include <cstring>

struct FsFileData {
    std::vector<uint8_t> bytes;
    bool isDir = false;
};

class FsShimStore {
public:
    std::map<std::string, FsFileData> entries;

    static FsShimStore& instance() {
        static FsShimStore s;
        return s;
    }
};

class File {
    std::string path_;
    bool valid_ = false;
    size_t readPos_ = 0;
    std::vector<uint8_t>* writeBuf_ = nullptr;
    std::vector<std::string> dirChildren_;
    size_t dirPos_ = 0;

public:
    File() = default;

    static File openRead(const std::string& path) {
        File f;
        auto& store = FsShimStore::instance().entries;
        auto it = store.find(path);
        if (it == store.end()) return f;
        f.path_ = path;
        f.valid_ = true;
        if (it->second.isDir) {
            for (auto& kv : store) {
                if (kv.first.size() > path.size() + 1 && kv.first.compare(0, path.size(), path) == 0 &&
                    kv.first[path.size()] == '/' && kv.first.find('/', path.size() + 1) == std::string::npos) {
                    f.dirChildren_.push_back(kv.first);
                }
            }
        }
        return f;
    }

    static File openWrite(const std::string& path) {
        File f;
        f.path_ = path;
        f.valid_ = true;
        auto& store = FsShimStore::instance().entries;
        store[path] = FsFileData();
        f.writeBuf_ = &store[path].bytes;
        return f;
    }

    operator bool() const { return valid_; }

    size_t size() const {
        auto it = FsShimStore::instance().entries.find(path_);
        return it != FsShimStore::instance().entries.end() ? it->second.bytes.size() : 0;
    }

    const char* name() const {
        static thread_local std::string base;
        size_t pos = path_.find_last_of('/');
        base = (pos == std::string::npos) ? path_ : path_.substr(pos + 1);
        return base.c_str();
    }

    bool isDirectory() const {
        auto it = FsShimStore::instance().entries.find(path_);
        return it != FsShimStore::instance().entries.end() && it->second.isDir;
    }

    size_t read(uint8_t* buf, size_t len) {
        auto it = FsShimStore::instance().entries.find(path_);
        if (it == FsShimStore::instance().entries.end()) return 0;
        size_t avail = it->second.bytes.size() - readPos_;
        size_t n = len < avail ? len : avail;
        memcpy(buf, it->second.bytes.data() + readPos_, n);
        readPos_ += n;
        return n;
    }

    size_t write(const uint8_t* buf, size_t len) {
        if (!writeBuf_) return 0;
        writeBuf_->insert(writeBuf_->end(), buf, buf + len);
        return len;
    }

    void close() {}

    File openNextFile() {
        if (dirPos_ >= dirChildren_.size()) return File();
        return openRead(dirChildren_[dirPos_++]);
    }
};

class LittleFsMock {
public:
    bool exists(const std::string& path) {
        return FsShimStore::instance().entries.count(path) > 0;
    }
    void mkdir(const std::string& path) {
        FsShimStore::instance().entries[path].isDir = true;
    }
    void remove(const std::string& path) {
        FsShimStore::instance().entries.erase(path);
    }
    File open(const std::string& path, const char* mode = "r") {
        if (mode[0] == 'w') return File::openWrite(path);
        return File::openRead(path);
    }
};

inline LittleFsMock LittleFS;
