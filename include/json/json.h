#ifndef WHITEDNS_LOCAL_JSON_H
#define WHITEDNS_LOCAL_JSON_H

#include <cstdint>
#include <iterator>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace Json {

using UInt64 = std::uint64_t;

enum ValueType {
    nullValue,
    intValue,
    uintValue,
    realValue,
    stringValue,
    booleanValue,
    arrayValue,
    objectValue
};

class Value {
public:
    Value() = default;
    explicit Value(ValueType type) : type_(type) {}
    Value(const char* value) : type_(stringValue), string_value_(value ? value : "") {}
    Value(const std::string& value) : type_(stringValue), string_value_(value) {}
    Value(bool value) : type_(booleanValue), bool_value_(value) {}
    Value(int value) : type_(intValue), int_value_(value) {}
    Value(UInt64 value) : type_(uintValue), uint_value_(value) {}

    Value& operator=(const char* value) {
        type_ = stringValue;
        string_value_ = value ? value : "";
        return *this;
    }

    Value& operator=(const std::string& value) {
        type_ = stringValue;
        string_value_ = value;
        return *this;
    }

    Value& operator=(bool value) {
        type_ = booleanValue;
        bool_value_ = value;
        return *this;
    }

    Value& operator=(int value) {
        type_ = intValue;
        int_value_ = value;
        return *this;
    }

    Value& operator=(UInt64 value) {
        type_ = uintValue;
        uint_value_ = value;
        return *this;
    }

    Value& operator[](const std::string& key) {
        if (type_ != objectValue) {
            type_ = objectValue;
            object_value_.clear();
        }
        return object_value_[key];
    }

    const Value& operator[](const std::string& key) const {
        static const Value null_value;
        if (type_ != objectValue) return null_value;
        auto it = object_value_.find(key);
        return it != object_value_.end() ? it->second : null_value;
    }

    bool isNull() const {
        return type_ == nullValue;
    }

    bool isArray() const {
        return type_ == arrayValue;
    }

    bool isObject() const {
        return type_ == objectValue;
    }

    std::string asString() const {
        return string_value_;
    }

    int asInt() const {
        return int_value_;
    }

    bool asBool() const {
        return bool_value_;
    }

    const std::vector<Value>& asArray() const {
        return array_value_;
    }

    void append(const Value& value) {
        if (type_ != arrayValue) {
            type_ = arrayValue;
            array_value_.clear();
        }
        array_value_.push_back(value);
    }

    bool empty() const {
        if (type_ == arrayValue) return array_value_.empty();
        if (type_ == objectValue) return object_value_.empty();
        if (type_ == stringValue) return string_value_.empty();
        return type_ == nullValue;
    }

    size_t size() const {
        if (type_ == arrayValue) return array_value_.size();
        if (type_ == objectValue) return object_value_.size();
        if (type_ == stringValue) return string_value_.size();
        return 0;
    }

    using iterator = std::vector<Value>::iterator;
    using const_iterator = std::vector<Value>::const_iterator;
    iterator begin() {
        if (type_ != arrayValue) {
            type_ = arrayValue;
            array_value_.clear();
        }
        return array_value_.begin();
    }
    iterator end() {
        if (type_ != arrayValue) {
            type_ = arrayValue;
            array_value_.clear();
        }
        return array_value_.end();
    }
    const_iterator begin() const { return array_value_.begin(); }
    const_iterator end() const { return array_value_.end(); }

    Value& operator[](size_t index) {
        if (type_ != arrayValue) {
            type_ = arrayValue;
            array_value_.clear();
        }
        if (index >= array_value_.size()) array_value_.resize(index + 1);
        return array_value_[index];
    }
    const Value& operator[](size_t index) const {
        static const Value null_value;
        if (type_ != arrayValue || index >= array_value_.size()) return null_value;
        return array_value_[index];
    }

    bool find(const std::string& needle) const {
        return string_value_.find(needle) != std::string::npos;
    }

    std::string toStyledString() const {
        std::ostringstream out;
        write(out, 0);
        out << "\n";
        return out.str();
    }

private:
    static std::string escape(const std::string& value) {
        std::ostringstream out;
        for (unsigned char c : value) {
            switch (c) {
                case '\\': out << "\\\\"; break;
                case '"': out << "\\\""; break;
                case '\b': out << "\\b"; break;
                case '\f': out << "\\f"; break;
                case '\n': out << "\\n"; break;
                case '\r': out << "\\r"; break;
                case '\t': out << "\\t"; break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        out << "\\u00";
                        const char* hex = "0123456789abcdef";
                        out << hex[(c >> 4) & 0x0f] << hex[c & 0x0f];
                    } else {
                        out << c;
                    }
            }
        }
        return out.str();
    }

    static void indent(std::ostringstream& out, int depth) {
        for (int i = 0; i < depth; ++i) out << "  ";
    }

    void write(std::ostringstream& out, int depth) const {
        switch (type_) {
            case nullValue:
                out << "null";
                break;
            case intValue:
                out << int_value_;
                break;
            case uintValue:
                out << uint_value_;
                break;
            case realValue:
                out << real_value_;
                break;
            case stringValue:
                out << '"' << escape(string_value_) << '"';
                break;
            case booleanValue:
                out << (bool_value_ ? "true" : "false");
                break;
            case arrayValue:
                out << "[";
                for (size_t i = 0; i < array_value_.size(); ++i) {
                    out << "\n";
                    indent(out, depth + 1);
                    array_value_[i].write(out, depth + 1);
                    if (i + 1 < array_value_.size()) out << ",";
                }
                if (!array_value_.empty()) {
                    out << "\n";
                    indent(out, depth);
                }
                out << "]";
                break;
            case objectValue:
                out << "{";
                for (auto it = object_value_.begin(); it != object_value_.end(); ++it) {
                    out << "\n";
                    indent(out, depth + 1);
                    out << '"' << escape(it->first) << "\": ";
                    it->second.write(out, depth + 1);
                    if (std::next(it) != object_value_.end()) out << ",";
                }
                if (!object_value_.empty()) {
                    out << "\n";
                    indent(out, depth);
                }
                out << "}";
                break;
        }
    }

    ValueType type_ = nullValue;
    std::string string_value_;
    bool bool_value_ = false;
    int int_value_ = 0;
    UInt64 uint_value_ = 0;
    double real_value_ = 0.0;
    std::vector<Value> array_value_;
    std::map<std::string, Value> object_value_;
};

} // namespace Json

#endif // WHITEDNS_LOCAL_JSON_H
