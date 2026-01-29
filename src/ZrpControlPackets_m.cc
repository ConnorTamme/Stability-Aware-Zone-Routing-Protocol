//
// Generated file, do not edit! Created by opp_msgtool 6.3 from ZrpControlPackets.msg.
//

// Disable warnings about unused variables, empty switch stmts, etc:
#ifdef _MSC_VER
#  pragma warning(disable:4101)
#  pragma warning(disable:4065)
#endif

#if defined(__clang__)
#  pragma clang diagnostic ignored "-Wshadow"
#  pragma clang diagnostic ignored "-Wconversion"
#  pragma clang diagnostic ignored "-Wunused-parameter"
#  pragma clang diagnostic ignored "-Wc++98-compat"
#  pragma clang diagnostic ignored "-Wunreachable-code-break"
#  pragma clang diagnostic ignored "-Wold-style-cast"
#elif defined(__GNUC__)
#  pragma GCC diagnostic ignored "-Wshadow"
#  pragma GCC diagnostic ignored "-Wconversion"
#  pragma GCC diagnostic ignored "-Wunused-parameter"
#  pragma GCC diagnostic ignored "-Wold-style-cast"
#  pragma GCC diagnostic ignored "-Wsuggest-attribute=noreturn"
#  pragma GCC diagnostic ignored "-Wfloat-conversion"
#endif

#include <iostream>
#include <sstream>
#include <memory>
#include <type_traits>
#include "ZrpControlPackets_m.h"

namespace omnetpp {

// Template pack/unpack rules. They are declared *after* a1l type-specific pack functions for multiple reasons.
// They are in the omnetpp namespace, to allow them to be found by argument-dependent lookup via the cCommBuffer argument

// Packing/unpacking an std::vector
template<typename T, typename A>
void doParsimPacking(omnetpp::cCommBuffer *buffer, const std::vector<T,A>& v)
{
    int n = v.size();
    doParsimPacking(buffer, n);
    for (int i = 0; i < n; i++)
        doParsimPacking(buffer, v[i]);
}

template<typename T, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer *buffer, std::vector<T,A>& v)
{
    int n;
    doParsimUnpacking(buffer, n);
    v.resize(n);
    for (int i = 0; i < n; i++)
        doParsimUnpacking(buffer, v[i]);
}

// Packing/unpacking an std::list
template<typename T, typename A>
void doParsimPacking(omnetpp::cCommBuffer *buffer, const std::list<T,A>& l)
{
    doParsimPacking(buffer, (int)l.size());
    for (typename std::list<T,A>::const_iterator it = l.begin(); it != l.end(); ++it)
        doParsimPacking(buffer, (T&)*it);
}

template<typename T, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer *buffer, std::list<T,A>& l)
{
    int n;
    doParsimUnpacking(buffer, n);
    for (int i = 0; i < n; i++) {
        l.push_back(T());
        doParsimUnpacking(buffer, l.back());
    }
}

// Packing/unpacking an std::set
template<typename T, typename Tr, typename A>
void doParsimPacking(omnetpp::cCommBuffer *buffer, const std::set<T,Tr,A>& s)
{
    doParsimPacking(buffer, (int)s.size());
    for (typename std::set<T,Tr,A>::const_iterator it = s.begin(); it != s.end(); ++it)
        doParsimPacking(buffer, *it);
}

template<typename T, typename Tr, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer *buffer, std::set<T,Tr,A>& s)
{
    int n;
    doParsimUnpacking(buffer, n);
    for (int i = 0; i < n; i++) {
        T x;
        doParsimUnpacking(buffer, x);
        s.insert(x);
    }
}

// Packing/unpacking an std::map
template<typename K, typename V, typename Tr, typename A>
void doParsimPacking(omnetpp::cCommBuffer *buffer, const std::map<K,V,Tr,A>& m)
{
    doParsimPacking(buffer, (int)m.size());
    for (typename std::map<K,V,Tr,A>::const_iterator it = m.begin(); it != m.end(); ++it) {
        doParsimPacking(buffer, it->first);
        doParsimPacking(buffer, it->second);
    }
}

template<typename K, typename V, typename Tr, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer *buffer, std::map<K,V,Tr,A>& m)
{
    int n;
    doParsimUnpacking(buffer, n);
    for (int i = 0; i < n; i++) {
        K k; V v;
        doParsimUnpacking(buffer, k);
        doParsimUnpacking(buffer, v);
        m[k] = v;
    }
}

// Default pack/unpack function for arrays
template<typename T>
void doParsimArrayPacking(omnetpp::cCommBuffer *b, const T *t, int n)
{
    for (int i = 0; i < n; i++)
        doParsimPacking(b, t[i]);
}

template<typename T>
void doParsimArrayUnpacking(omnetpp::cCommBuffer *b, T *t, int n)
{
    for (int i = 0; i < n; i++)
        doParsimUnpacking(b, t[i]);
}

// Default rule to prevent compiler from choosing base class' doParsimPacking() function
template<typename T>
void doParsimPacking(omnetpp::cCommBuffer *, const T& t)
{
    throw omnetpp::cRuntimeError("Parsim error: No doParsimPacking() function for type %s", omnetpp::opp_typename(typeid(t)));
}

template<typename T>
void doParsimUnpacking(omnetpp::cCommBuffer *, T& t)
{
    throw omnetpp::cRuntimeError("Parsim error: No doParsimUnpacking() function for type %s", omnetpp::opp_typename(typeid(t)));
}

}  // namespace omnetpp

namespace inet {
namespace zrp {

Register_Class(NDP_Hello)

NDP_Hello::NDP_Hello() : ::inet::FieldsChunk()
{
}

NDP_Hello::NDP_Hello(const NDP_Hello& other) : ::inet::FieldsChunk(other)
{
    copy(other);
}

NDP_Hello::~NDP_Hello()
{
}

NDP_Hello& NDP_Hello::operator=(const NDP_Hello& other)
{
    if (this == &other) return *this;
    ::inet::FieldsChunk::operator=(other);
    copy(other);
    return *this;
}

void NDP_Hello::copy(const NDP_Hello& other)
{
    this->nodeAddress = other.nodeAddress;
    this->seqNum = other.seqNum;
}

void NDP_Hello::parsimPack(omnetpp::cCommBuffer *b) const
{
    ::inet::FieldsChunk::parsimPack(b);
    doParsimPacking(b,this->nodeAddress);
    doParsimPacking(b,this->seqNum);
}

void NDP_Hello::parsimUnpack(omnetpp::cCommBuffer *b)
{
    ::inet::FieldsChunk::parsimUnpack(b);
    doParsimUnpacking(b,this->nodeAddress);
    doParsimUnpacking(b,this->seqNum);
}

const ::inet::L3Address& NDP_Hello::getNodeAddress() const
{
    return this->nodeAddress;
}

void NDP_Hello::setNodeAddress(const ::inet::L3Address& nodeAddress)
{
    handleChange();
    this->nodeAddress = nodeAddress;
}

uint16_t NDP_Hello::getSeqNum() const
{
    return this->seqNum;
}

void NDP_Hello::setSeqNum(uint16_t seqNum)
{
    handleChange();
    this->seqNum = seqNum;
}

class NDP_HelloDescriptor : public omnetpp::cClassDescriptor
{
  private:
    mutable const char **propertyNames;
    enum FieldConstants {
        FIELD_nodeAddress,
        FIELD_seqNum,
    };
  public:
    NDP_HelloDescriptor();
    virtual ~NDP_HelloDescriptor();

    virtual bool doesSupport(omnetpp::cObject *obj) const override;
    virtual const char **getPropertyNames() const override;
    virtual const char *getProperty(const char *propertyName) const override;
    virtual int getFieldCount() const override;
    virtual const char *getFieldName(int field) const override;
    virtual int findField(const char *fieldName) const override;
    virtual unsigned int getFieldTypeFlags(int field) const override;
    virtual const char *getFieldTypeString(int field) const override;
    virtual const char **getFieldPropertyNames(int field) const override;
    virtual const char *getFieldProperty(int field, const char *propertyName) const override;
    virtual int getFieldArraySize(omnetpp::any_ptr object, int field) const override;
    virtual void setFieldArraySize(omnetpp::any_ptr object, int field, int size) const override;

    virtual const char *getFieldDynamicTypeString(omnetpp::any_ptr object, int field, int i) const override;
    virtual std::string getFieldValueAsString(omnetpp::any_ptr object, int field, int i) const override;
    virtual void setFieldValueAsString(omnetpp::any_ptr object, int field, int i, const char *value) const override;
    virtual omnetpp::cValue getFieldValue(omnetpp::any_ptr object, int field, int i) const override;
    virtual void setFieldValue(omnetpp::any_ptr object, int field, int i, const omnetpp::cValue& value) const override;

    virtual const char *getFieldStructName(int field) const override;
    virtual omnetpp::any_ptr getFieldStructValuePointer(omnetpp::any_ptr object, int field, int i) const override;
    virtual void setFieldStructValuePointer(omnetpp::any_ptr object, int field, int i, omnetpp::any_ptr ptr) const override;
};

Register_ClassDescriptor(NDP_HelloDescriptor)

NDP_HelloDescriptor::NDP_HelloDescriptor() : omnetpp::cClassDescriptor(omnetpp::opp_typename(typeid(inet::zrp::NDP_Hello)), "inet::FieldsChunk")
{
    propertyNames = nullptr;
}

NDP_HelloDescriptor::~NDP_HelloDescriptor()
{
    delete[] propertyNames;
}

bool NDP_HelloDescriptor::doesSupport(omnetpp::cObject *obj) const
{
    return dynamic_cast<NDP_Hello *>(obj)!=nullptr;
}

const char **NDP_HelloDescriptor::getPropertyNames() const
{
    if (!propertyNames) {
        static const char *names[] = {  nullptr };
        omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
        const char **baseNames = base ? base->getPropertyNames() : nullptr;
        propertyNames = mergeLists(baseNames, names);
    }
    return propertyNames;
}

const char *NDP_HelloDescriptor::getProperty(const char *propertyName) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    return base ? base->getProperty(propertyName) : nullptr;
}

int NDP_HelloDescriptor::getFieldCount() const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    return base ? 2+base->getFieldCount() : 2;
}

unsigned int NDP_HelloDescriptor::getFieldTypeFlags(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldTypeFlags(field);
        field -= base->getFieldCount();
    }
    static unsigned int fieldTypeFlags[] = {
        0,    // FIELD_nodeAddress
        FD_ISEDITABLE,    // FIELD_seqNum
    };
    return (field >= 0 && field < 2) ? fieldTypeFlags[field] : 0;
}

const char *NDP_HelloDescriptor::getFieldName(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldName(field);
        field -= base->getFieldCount();
    }
    static const char *fieldNames[] = {
        "nodeAddress",
        "seqNum",
    };
    return (field >= 0 && field < 2) ? fieldNames[field] : nullptr;
}

int NDP_HelloDescriptor::findField(const char *fieldName) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    int baseIndex = base ? base->getFieldCount() : 0;
    if (strcmp(fieldName, "nodeAddress") == 0) return baseIndex + 0;
    if (strcmp(fieldName, "seqNum") == 0) return baseIndex + 1;
    return base ? base->findField(fieldName) : -1;
}

const char *NDP_HelloDescriptor::getFieldTypeString(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldTypeString(field);
        field -= base->getFieldCount();
    }
    static const char *fieldTypeStrings[] = {
        "inet::L3Address",    // FIELD_nodeAddress
        "uint16_t",    // FIELD_seqNum
    };
    return (field >= 0 && field < 2) ? fieldTypeStrings[field] : nullptr;
}

const char **NDP_HelloDescriptor::getFieldPropertyNames(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldPropertyNames(field);
        field -= base->getFieldCount();
    }
    switch (field) {
        default: return nullptr;
    }
}

const char *NDP_HelloDescriptor::getFieldProperty(int field, const char *propertyName) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldProperty(field, propertyName);
        field -= base->getFieldCount();
    }
    switch (field) {
        default: return nullptr;
    }
}

int NDP_HelloDescriptor::getFieldArraySize(omnetpp::any_ptr object, int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldArraySize(object, field);
        field -= base->getFieldCount();
    }
    NDP_Hello *pp = omnetpp::fromAnyPtr<NDP_Hello>(object); (void)pp;
    switch (field) {
        default: return 0;
    }
}

void NDP_HelloDescriptor::setFieldArraySize(omnetpp::any_ptr object, int field, int size) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldArraySize(object, field, size);
            return;
        }
        field -= base->getFieldCount();
    }
    NDP_Hello *pp = omnetpp::fromAnyPtr<NDP_Hello>(object); (void)pp;
    switch (field) {
        default: throw omnetpp::cRuntimeError("Cannot set array size of field %d of class 'NDP_Hello'", field);
    }
}

const char *NDP_HelloDescriptor::getFieldDynamicTypeString(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldDynamicTypeString(object,field,i);
        field -= base->getFieldCount();
    }
    NDP_Hello *pp = omnetpp::fromAnyPtr<NDP_Hello>(object); (void)pp;
    switch (field) {
        default: return nullptr;
    }
}

std::string NDP_HelloDescriptor::getFieldValueAsString(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldValueAsString(object,field,i);
        field -= base->getFieldCount();
    }
    NDP_Hello *pp = omnetpp::fromAnyPtr<NDP_Hello>(object); (void)pp;
    switch (field) {
        case FIELD_nodeAddress: return pp->getNodeAddress().str();
        case FIELD_seqNum: return ulong2string(pp->getSeqNum());
        default: return "";
    }
}

void NDP_HelloDescriptor::setFieldValueAsString(omnetpp::any_ptr object, int field, int i, const char *value) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldValueAsString(object, field, i, value);
            return;
        }
        field -= base->getFieldCount();
    }
    NDP_Hello *pp = omnetpp::fromAnyPtr<NDP_Hello>(object); (void)pp;
    switch (field) {
        case FIELD_seqNum: pp->setSeqNum(string2ulong(value)); break;
        default: throw omnetpp::cRuntimeError("Cannot set field %d of class 'NDP_Hello'", field);
    }
}

omnetpp::cValue NDP_HelloDescriptor::getFieldValue(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldValue(object,field,i);
        field -= base->getFieldCount();
    }
    NDP_Hello *pp = omnetpp::fromAnyPtr<NDP_Hello>(object); (void)pp;
    switch (field) {
        case FIELD_nodeAddress: return omnetpp::toAnyPtr(&pp->getNodeAddress()); break;
        case FIELD_seqNum: return (omnetpp::intval_t)(pp->getSeqNum());
        default: throw omnetpp::cRuntimeError("Cannot return field %d of class 'NDP_Hello' as cValue -- field index out of range?", field);
    }
}

void NDP_HelloDescriptor::setFieldValue(omnetpp::any_ptr object, int field, int i, const omnetpp::cValue& value) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldValue(object, field, i, value);
            return;
        }
        field -= base->getFieldCount();
    }
    NDP_Hello *pp = omnetpp::fromAnyPtr<NDP_Hello>(object); (void)pp;
    switch (field) {
        case FIELD_seqNum: pp->setSeqNum(omnetpp::checked_int_cast<uint16_t>(value.intValue())); break;
        default: throw omnetpp::cRuntimeError("Cannot set field %d of class 'NDP_Hello'", field);
    }
}

const char *NDP_HelloDescriptor::getFieldStructName(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldStructName(field);
        field -= base->getFieldCount();
    }
    switch (field) {
        default: return nullptr;
    };
}

omnetpp::any_ptr NDP_HelloDescriptor::getFieldStructValuePointer(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldStructValuePointer(object, field, i);
        field -= base->getFieldCount();
    }
    NDP_Hello *pp = omnetpp::fromAnyPtr<NDP_Hello>(object); (void)pp;
    switch (field) {
        case FIELD_nodeAddress: return omnetpp::toAnyPtr(&pp->getNodeAddress()); break;
        default: return omnetpp::any_ptr(nullptr);
    }
}

void NDP_HelloDescriptor::setFieldStructValuePointer(omnetpp::any_ptr object, int field, int i, omnetpp::any_ptr ptr) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldStructValuePointer(object, field, i, ptr);
            return;
        }
        field -= base->getFieldCount();
    }
    NDP_Hello *pp = omnetpp::fromAnyPtr<NDP_Hello>(object); (void)pp;
    switch (field) {
        default: throw omnetpp::cRuntimeError("Cannot set field %d of class 'NDP_Hello'", field);
    }
}

IARP_MetricData::IARP_MetricData()
{
}

void __doPacking(omnetpp::cCommBuffer *b, const IARP_MetricData& a)
{
    doParsimPacking(b,a.reserved);
    doParsimPacking(b,a.metricType);
    doParsimPacking(b,a.metricValue);
}

void __doUnpacking(omnetpp::cCommBuffer *b, IARP_MetricData& a)
{
    doParsimUnpacking(b,a.reserved);
    doParsimUnpacking(b,a.metricType);
    doParsimUnpacking(b,a.metricValue);
}

class IARP_MetricDataDescriptor : public omnetpp::cClassDescriptor
{
  private:
    mutable const char **propertyNames;
    enum FieldConstants {
        FIELD_reserved,
        FIELD_metricType,
        FIELD_metricValue,
    };
  public:
    IARP_MetricDataDescriptor();
    virtual ~IARP_MetricDataDescriptor();

    virtual bool doesSupport(omnetpp::cObject *obj) const override;
    virtual const char **getPropertyNames() const override;
    virtual const char *getProperty(const char *propertyName) const override;
    virtual int getFieldCount() const override;
    virtual const char *getFieldName(int field) const override;
    virtual int findField(const char *fieldName) const override;
    virtual unsigned int getFieldTypeFlags(int field) const override;
    virtual const char *getFieldTypeString(int field) const override;
    virtual const char **getFieldPropertyNames(int field) const override;
    virtual const char *getFieldProperty(int field, const char *propertyName) const override;
    virtual int getFieldArraySize(omnetpp::any_ptr object, int field) const override;
    virtual void setFieldArraySize(omnetpp::any_ptr object, int field, int size) const override;

    virtual const char *getFieldDynamicTypeString(omnetpp::any_ptr object, int field, int i) const override;
    virtual std::string getFieldValueAsString(omnetpp::any_ptr object, int field, int i) const override;
    virtual void setFieldValueAsString(omnetpp::any_ptr object, int field, int i, const char *value) const override;
    virtual omnetpp::cValue getFieldValue(omnetpp::any_ptr object, int field, int i) const override;
    virtual void setFieldValue(omnetpp::any_ptr object, int field, int i, const omnetpp::cValue& value) const override;

    virtual const char *getFieldStructName(int field) const override;
    virtual omnetpp::any_ptr getFieldStructValuePointer(omnetpp::any_ptr object, int field, int i) const override;
    virtual void setFieldStructValuePointer(omnetpp::any_ptr object, int field, int i, omnetpp::any_ptr ptr) const override;
};

Register_ClassDescriptor(IARP_MetricDataDescriptor)

IARP_MetricDataDescriptor::IARP_MetricDataDescriptor() : omnetpp::cClassDescriptor(omnetpp::opp_typename(typeid(inet::zrp::IARP_MetricData)), "")
{
    propertyNames = nullptr;
}

IARP_MetricDataDescriptor::~IARP_MetricDataDescriptor()
{
    delete[] propertyNames;
}

bool IARP_MetricDataDescriptor::doesSupport(omnetpp::cObject *obj) const
{
    return dynamic_cast<IARP_MetricData *>(obj)!=nullptr;
}

const char **IARP_MetricDataDescriptor::getPropertyNames() const
{
    if (!propertyNames) {
        static const char *names[] = {  nullptr };
        omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
        const char **baseNames = base ? base->getPropertyNames() : nullptr;
        propertyNames = mergeLists(baseNames, names);
    }
    return propertyNames;
}

const char *IARP_MetricDataDescriptor::getProperty(const char *propertyName) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    return base ? base->getProperty(propertyName) : nullptr;
}

int IARP_MetricDataDescriptor::getFieldCount() const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    return base ? 3+base->getFieldCount() : 3;
}

unsigned int IARP_MetricDataDescriptor::getFieldTypeFlags(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldTypeFlags(field);
        field -= base->getFieldCount();
    }
    static unsigned int fieldTypeFlags[] = {
        FD_ISEDITABLE,    // FIELD_reserved
        FD_ISEDITABLE,    // FIELD_metricType
        FD_ISEDITABLE,    // FIELD_metricValue
    };
    return (field >= 0 && field < 3) ? fieldTypeFlags[field] : 0;
}

const char *IARP_MetricDataDescriptor::getFieldName(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldName(field);
        field -= base->getFieldCount();
    }
    static const char *fieldNames[] = {
        "reserved",
        "metricType",
        "metricValue",
    };
    return (field >= 0 && field < 3) ? fieldNames[field] : nullptr;
}

int IARP_MetricDataDescriptor::findField(const char *fieldName) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    int baseIndex = base ? base->getFieldCount() : 0;
    if (strcmp(fieldName, "reserved") == 0) return baseIndex + 0;
    if (strcmp(fieldName, "metricType") == 0) return baseIndex + 1;
    if (strcmp(fieldName, "metricValue") == 0) return baseIndex + 2;
    return base ? base->findField(fieldName) : -1;
}

const char *IARP_MetricDataDescriptor::getFieldTypeString(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldTypeString(field);
        field -= base->getFieldCount();
    }
    static const char *fieldTypeStrings[] = {
        "uint8_t",    // FIELD_reserved
        "uint8_t",    // FIELD_metricType
        "uint16_t",    // FIELD_metricValue
    };
    return (field >= 0 && field < 3) ? fieldTypeStrings[field] : nullptr;
}

const char **IARP_MetricDataDescriptor::getFieldPropertyNames(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldPropertyNames(field);
        field -= base->getFieldCount();
    }
    switch (field) {
        default: return nullptr;
    }
}

const char *IARP_MetricDataDescriptor::getFieldProperty(int field, const char *propertyName) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldProperty(field, propertyName);
        field -= base->getFieldCount();
    }
    switch (field) {
        default: return nullptr;
    }
}

int IARP_MetricDataDescriptor::getFieldArraySize(omnetpp::any_ptr object, int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldArraySize(object, field);
        field -= base->getFieldCount();
    }
    IARP_MetricData *pp = omnetpp::fromAnyPtr<IARP_MetricData>(object); (void)pp;
    switch (field) {
        default: return 0;
    }
}

void IARP_MetricDataDescriptor::setFieldArraySize(omnetpp::any_ptr object, int field, int size) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldArraySize(object, field, size);
            return;
        }
        field -= base->getFieldCount();
    }
    IARP_MetricData *pp = omnetpp::fromAnyPtr<IARP_MetricData>(object); (void)pp;
    switch (field) {
        default: throw omnetpp::cRuntimeError("Cannot set array size of field %d of class 'IARP_MetricData'", field);
    }
}

const char *IARP_MetricDataDescriptor::getFieldDynamicTypeString(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldDynamicTypeString(object,field,i);
        field -= base->getFieldCount();
    }
    IARP_MetricData *pp = omnetpp::fromAnyPtr<IARP_MetricData>(object); (void)pp;
    switch (field) {
        default: return nullptr;
    }
}

std::string IARP_MetricDataDescriptor::getFieldValueAsString(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldValueAsString(object,field,i);
        field -= base->getFieldCount();
    }
    IARP_MetricData *pp = omnetpp::fromAnyPtr<IARP_MetricData>(object); (void)pp;
    switch (field) {
        case FIELD_reserved: return ulong2string(pp->reserved);
        case FIELD_metricType: return ulong2string(pp->metricType);
        case FIELD_metricValue: return ulong2string(pp->metricValue);
        default: return "";
    }
}

void IARP_MetricDataDescriptor::setFieldValueAsString(omnetpp::any_ptr object, int field, int i, const char *value) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldValueAsString(object, field, i, value);
            return;
        }
        field -= base->getFieldCount();
    }
    IARP_MetricData *pp = omnetpp::fromAnyPtr<IARP_MetricData>(object); (void)pp;
    switch (field) {
        case FIELD_reserved: pp->reserved = string2ulong(value); break;
        case FIELD_metricType: pp->metricType = string2ulong(value); break;
        case FIELD_metricValue: pp->metricValue = string2ulong(value); break;
        default: throw omnetpp::cRuntimeError("Cannot set field %d of class 'IARP_MetricData'", field);
    }
}

omnetpp::cValue IARP_MetricDataDescriptor::getFieldValue(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldValue(object,field,i);
        field -= base->getFieldCount();
    }
    IARP_MetricData *pp = omnetpp::fromAnyPtr<IARP_MetricData>(object); (void)pp;
    switch (field) {
        case FIELD_reserved: return (omnetpp::intval_t)(pp->reserved);
        case FIELD_metricType: return (omnetpp::intval_t)(pp->metricType);
        case FIELD_metricValue: return (omnetpp::intval_t)(pp->metricValue);
        default: throw omnetpp::cRuntimeError("Cannot return field %d of class 'IARP_MetricData' as cValue -- field index out of range?", field);
    }
}

void IARP_MetricDataDescriptor::setFieldValue(omnetpp::any_ptr object, int field, int i, const omnetpp::cValue& value) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldValue(object, field, i, value);
            return;
        }
        field -= base->getFieldCount();
    }
    IARP_MetricData *pp = omnetpp::fromAnyPtr<IARP_MetricData>(object); (void)pp;
    switch (field) {
        case FIELD_reserved: pp->reserved = omnetpp::checked_int_cast<uint8_t>(value.intValue()); break;
        case FIELD_metricType: pp->metricType = omnetpp::checked_int_cast<uint8_t>(value.intValue()); break;
        case FIELD_metricValue: pp->metricValue = omnetpp::checked_int_cast<uint16_t>(value.intValue()); break;
        default: throw omnetpp::cRuntimeError("Cannot set field %d of class 'IARP_MetricData'", field);
    }
}

const char *IARP_MetricDataDescriptor::getFieldStructName(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldStructName(field);
        field -= base->getFieldCount();
    }
    switch (field) {
        default: return nullptr;
    };
}

omnetpp::any_ptr IARP_MetricDataDescriptor::getFieldStructValuePointer(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldStructValuePointer(object, field, i);
        field -= base->getFieldCount();
    }
    IARP_MetricData *pp = omnetpp::fromAnyPtr<IARP_MetricData>(object); (void)pp;
    switch (field) {
        default: return omnetpp::any_ptr(nullptr);
    }
}

void IARP_MetricDataDescriptor::setFieldStructValuePointer(omnetpp::any_ptr object, int field, int i, omnetpp::any_ptr ptr) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldStructValuePointer(object, field, i, ptr);
            return;
        }
        field -= base->getFieldCount();
    }
    IARP_MetricData *pp = omnetpp::fromAnyPtr<IARP_MetricData>(object); (void)pp;
    switch (field) {
        default: throw omnetpp::cRuntimeError("Cannot set field %d of class 'IARP_MetricData'", field);
    }
}

IARP_LinkDestData::IARP_LinkDestData()
{
}

void __doPacking(omnetpp::cCommBuffer *b, const IARP_LinkDestData& a)
{
    doParsimPacking(b,a.addr);
    doParsimArrayPacking(b,a.metrics,IARP_METRIC_COUNT);
}

void __doUnpacking(omnetpp::cCommBuffer *b, IARP_LinkDestData& a)
{
    doParsimUnpacking(b,a.addr);
    doParsimArrayUnpacking(b,a.metrics,IARP_METRIC_COUNT);
}

class IARP_LinkDestDataDescriptor : public omnetpp::cClassDescriptor
{
  private:
    mutable const char **propertyNames;
    enum FieldConstants {
        FIELD_addr,
        FIELD_metrics,
    };
  public:
    IARP_LinkDestDataDescriptor();
    virtual ~IARP_LinkDestDataDescriptor();

    virtual bool doesSupport(omnetpp::cObject *obj) const override;
    virtual const char **getPropertyNames() const override;
    virtual const char *getProperty(const char *propertyName) const override;
    virtual int getFieldCount() const override;
    virtual const char *getFieldName(int field) const override;
    virtual int findField(const char *fieldName) const override;
    virtual unsigned int getFieldTypeFlags(int field) const override;
    virtual const char *getFieldTypeString(int field) const override;
    virtual const char **getFieldPropertyNames(int field) const override;
    virtual const char *getFieldProperty(int field, const char *propertyName) const override;
    virtual int getFieldArraySize(omnetpp::any_ptr object, int field) const override;
    virtual void setFieldArraySize(omnetpp::any_ptr object, int field, int size) const override;

    virtual const char *getFieldDynamicTypeString(omnetpp::any_ptr object, int field, int i) const override;
    virtual std::string getFieldValueAsString(omnetpp::any_ptr object, int field, int i) const override;
    virtual void setFieldValueAsString(omnetpp::any_ptr object, int field, int i, const char *value) const override;
    virtual omnetpp::cValue getFieldValue(omnetpp::any_ptr object, int field, int i) const override;
    virtual void setFieldValue(omnetpp::any_ptr object, int field, int i, const omnetpp::cValue& value) const override;

    virtual const char *getFieldStructName(int field) const override;
    virtual omnetpp::any_ptr getFieldStructValuePointer(omnetpp::any_ptr object, int field, int i) const override;
    virtual void setFieldStructValuePointer(omnetpp::any_ptr object, int field, int i, omnetpp::any_ptr ptr) const override;
};

Register_ClassDescriptor(IARP_LinkDestDataDescriptor)

IARP_LinkDestDataDescriptor::IARP_LinkDestDataDescriptor() : omnetpp::cClassDescriptor(omnetpp::opp_typename(typeid(inet::zrp::IARP_LinkDestData)), "")
{
    propertyNames = nullptr;
}

IARP_LinkDestDataDescriptor::~IARP_LinkDestDataDescriptor()
{
    delete[] propertyNames;
}

bool IARP_LinkDestDataDescriptor::doesSupport(omnetpp::cObject *obj) const
{
    return dynamic_cast<IARP_LinkDestData *>(obj)!=nullptr;
}

const char **IARP_LinkDestDataDescriptor::getPropertyNames() const
{
    if (!propertyNames) {
        static const char *names[] = { "packetData",  nullptr };
        omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
        const char **baseNames = base ? base->getPropertyNames() : nullptr;
        propertyNames = mergeLists(baseNames, names);
    }
    return propertyNames;
}

const char *IARP_LinkDestDataDescriptor::getProperty(const char *propertyName) const
{
    if (!strcmp(propertyName, "packetData")) return "";
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    return base ? base->getProperty(propertyName) : nullptr;
}

int IARP_LinkDestDataDescriptor::getFieldCount() const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    return base ? 2+base->getFieldCount() : 2;
}

unsigned int IARP_LinkDestDataDescriptor::getFieldTypeFlags(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldTypeFlags(field);
        field -= base->getFieldCount();
    }
    static unsigned int fieldTypeFlags[] = {
        0,    // FIELD_addr
        FD_ISARRAY | FD_ISCOMPOUND,    // FIELD_metrics
    };
    return (field >= 0 && field < 2) ? fieldTypeFlags[field] : 0;
}

const char *IARP_LinkDestDataDescriptor::getFieldName(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldName(field);
        field -= base->getFieldCount();
    }
    static const char *fieldNames[] = {
        "addr",
        "metrics",
    };
    return (field >= 0 && field < 2) ? fieldNames[field] : nullptr;
}

int IARP_LinkDestDataDescriptor::findField(const char *fieldName) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    int baseIndex = base ? base->getFieldCount() : 0;
    if (strcmp(fieldName, "addr") == 0) return baseIndex + 0;
    if (strcmp(fieldName, "metrics") == 0) return baseIndex + 1;
    return base ? base->findField(fieldName) : -1;
}

const char *IARP_LinkDestDataDescriptor::getFieldTypeString(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldTypeString(field);
        field -= base->getFieldCount();
    }
    static const char *fieldTypeStrings[] = {
        "inet::L3Address",    // FIELD_addr
        "inet::zrp::IARP_MetricData",    // FIELD_metrics
    };
    return (field >= 0 && field < 2) ? fieldTypeStrings[field] : nullptr;
}

const char **IARP_LinkDestDataDescriptor::getFieldPropertyNames(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldPropertyNames(field);
        field -= base->getFieldCount();
    }
    switch (field) {
        default: return nullptr;
    }
}

const char *IARP_LinkDestDataDescriptor::getFieldProperty(int field, const char *propertyName) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldProperty(field, propertyName);
        field -= base->getFieldCount();
    }
    switch (field) {
        default: return nullptr;
    }
}

int IARP_LinkDestDataDescriptor::getFieldArraySize(omnetpp::any_ptr object, int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldArraySize(object, field);
        field -= base->getFieldCount();
    }
    IARP_LinkDestData *pp = omnetpp::fromAnyPtr<IARP_LinkDestData>(object); (void)pp;
    switch (field) {
        case FIELD_metrics: return IARP_METRIC_COUNT;
        default: return 0;
    }
}

void IARP_LinkDestDataDescriptor::setFieldArraySize(omnetpp::any_ptr object, int field, int size) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldArraySize(object, field, size);
            return;
        }
        field -= base->getFieldCount();
    }
    IARP_LinkDestData *pp = omnetpp::fromAnyPtr<IARP_LinkDestData>(object); (void)pp;
    switch (field) {
        default: throw omnetpp::cRuntimeError("Cannot set array size of field %d of class 'IARP_LinkDestData'", field);
    }
}

const char *IARP_LinkDestDataDescriptor::getFieldDynamicTypeString(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldDynamicTypeString(object,field,i);
        field -= base->getFieldCount();
    }
    IARP_LinkDestData *pp = omnetpp::fromAnyPtr<IARP_LinkDestData>(object); (void)pp;
    switch (field) {
        default: return nullptr;
    }
}

std::string IARP_LinkDestDataDescriptor::getFieldValueAsString(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldValueAsString(object,field,i);
        field -= base->getFieldCount();
    }
    IARP_LinkDestData *pp = omnetpp::fromAnyPtr<IARP_LinkDestData>(object); (void)pp;
    switch (field) {
        case FIELD_addr: return pp->addr.str();
        case FIELD_metrics: if (i >= IARP_METRIC_COUNT) return "";
                return "";
        default: return "";
    }
}

void IARP_LinkDestDataDescriptor::setFieldValueAsString(omnetpp::any_ptr object, int field, int i, const char *value) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldValueAsString(object, field, i, value);
            return;
        }
        field -= base->getFieldCount();
    }
    IARP_LinkDestData *pp = omnetpp::fromAnyPtr<IARP_LinkDestData>(object); (void)pp;
    switch (field) {
        default: throw omnetpp::cRuntimeError("Cannot set field %d of class 'IARP_LinkDestData'", field);
    }
}

omnetpp::cValue IARP_LinkDestDataDescriptor::getFieldValue(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldValue(object,field,i);
        field -= base->getFieldCount();
    }
    IARP_LinkDestData *pp = omnetpp::fromAnyPtr<IARP_LinkDestData>(object); (void)pp;
    switch (field) {
        case FIELD_addr: return omnetpp::toAnyPtr(&pp->addr); break;
        case FIELD_metrics: if (i >= IARP_METRIC_COUNT) return omnetpp::cValue();
                return omnetpp::toAnyPtr(&pp->metrics[i]); break;
        default: throw omnetpp::cRuntimeError("Cannot return field %d of class 'IARP_LinkDestData' as cValue -- field index out of range?", field);
    }
}

void IARP_LinkDestDataDescriptor::setFieldValue(omnetpp::any_ptr object, int field, int i, const omnetpp::cValue& value) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldValue(object, field, i, value);
            return;
        }
        field -= base->getFieldCount();
    }
    IARP_LinkDestData *pp = omnetpp::fromAnyPtr<IARP_LinkDestData>(object); (void)pp;
    switch (field) {
        default: throw omnetpp::cRuntimeError("Cannot set field %d of class 'IARP_LinkDestData'", field);
    }
}

const char *IARP_LinkDestDataDescriptor::getFieldStructName(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldStructName(field);
        field -= base->getFieldCount();
    }
    switch (field) {
        case FIELD_metrics: return omnetpp::opp_typename(typeid(IARP_MetricData));
        default: return nullptr;
    };
}

omnetpp::any_ptr IARP_LinkDestDataDescriptor::getFieldStructValuePointer(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldStructValuePointer(object, field, i);
        field -= base->getFieldCount();
    }
    IARP_LinkDestData *pp = omnetpp::fromAnyPtr<IARP_LinkDestData>(object); (void)pp;
    switch (field) {
        case FIELD_addr: return omnetpp::toAnyPtr(&pp->addr); break;
        case FIELD_metrics: return omnetpp::toAnyPtr(&pp->metrics[i]); break;
        default: return omnetpp::any_ptr(nullptr);
    }
}

void IARP_LinkDestDataDescriptor::setFieldStructValuePointer(omnetpp::any_ptr object, int field, int i, omnetpp::any_ptr ptr) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldStructValuePointer(object, field, i, ptr);
            return;
        }
        field -= base->getFieldCount();
    }
    IARP_LinkDestData *pp = omnetpp::fromAnyPtr<IARP_LinkDestData>(object); (void)pp;
    switch (field) {
        default: throw omnetpp::cRuntimeError("Cannot set field %d of class 'IARP_LinkDestData'", field);
    }
}

Register_Class(IARP_LinkStateUpdate)

IARP_LinkStateUpdate::IARP_LinkStateUpdate() : ::inet::FieldsChunk()
{
}

IARP_LinkStateUpdate::IARP_LinkStateUpdate(const IARP_LinkStateUpdate& other) : ::inet::FieldsChunk(other)
{
    copy(other);
}

IARP_LinkStateUpdate::~IARP_LinkStateUpdate()
{
    delete [] this->linkDestData;
}

IARP_LinkStateUpdate& IARP_LinkStateUpdate::operator=(const IARP_LinkStateUpdate& other)
{
    if (this == &other) return *this;
    ::inet::FieldsChunk::operator=(other);
    copy(other);
    return *this;
}

void IARP_LinkStateUpdate::copy(const IARP_LinkStateUpdate& other)
{
    this->sourceAddr = other.sourceAddr;
    this->seqNum = other.seqNum;
    this->radius = other.radius;
    this->TTL = other.TTL;
    this->reserved1 = other.reserved1;
    this->reserved2 = other.reserved2;
    this->linkDestCount = other.linkDestCount;
    delete [] this->linkDestData;
    this->linkDestData = (other.linkDestData_arraysize==0) ? nullptr : new IARP_LinkDestData[other.linkDestData_arraysize];
    linkDestData_arraysize = other.linkDestData_arraysize;
    for (size_t i = 0; i < linkDestData_arraysize; i++) {
        this->linkDestData[i] = other.linkDestData[i];
    }
}

void IARP_LinkStateUpdate::parsimPack(omnetpp::cCommBuffer *b) const
{
    ::inet::FieldsChunk::parsimPack(b);
    doParsimPacking(b,this->sourceAddr);
    doParsimPacking(b,this->seqNum);
    doParsimPacking(b,this->radius);
    doParsimPacking(b,this->TTL);
    doParsimPacking(b,this->reserved1);
    doParsimPacking(b,this->reserved2);
    doParsimPacking(b,this->linkDestCount);
    b->pack(linkDestData_arraysize);
    doParsimArrayPacking(b,this->linkDestData,linkDestData_arraysize);
}

void IARP_LinkStateUpdate::parsimUnpack(omnetpp::cCommBuffer *b)
{
    ::inet::FieldsChunk::parsimUnpack(b);
    doParsimUnpacking(b,this->sourceAddr);
    doParsimUnpacking(b,this->seqNum);
    doParsimUnpacking(b,this->radius);
    doParsimUnpacking(b,this->TTL);
    doParsimUnpacking(b,this->reserved1);
    doParsimUnpacking(b,this->reserved2);
    doParsimUnpacking(b,this->linkDestCount);
    delete [] this->linkDestData;
    b->unpack(linkDestData_arraysize);
    if (linkDestData_arraysize == 0) {
        this->linkDestData = nullptr;
    } else {
        this->linkDestData = new IARP_LinkDestData[linkDestData_arraysize];
        doParsimArrayUnpacking(b,this->linkDestData,linkDestData_arraysize);
    }
}

const ::inet::L3Address& IARP_LinkStateUpdate::getSourceAddr() const
{
    return this->sourceAddr;
}

void IARP_LinkStateUpdate::setSourceAddr(const ::inet::L3Address& sourceAddr)
{
    handleChange();
    this->sourceAddr = sourceAddr;
}

uint16_t IARP_LinkStateUpdate::getSeqNum() const
{
    return this->seqNum;
}

void IARP_LinkStateUpdate::setSeqNum(uint16_t seqNum)
{
    handleChange();
    this->seqNum = seqNum;
}

uint8_t IARP_LinkStateUpdate::getRadius() const
{
    return this->radius;
}

void IARP_LinkStateUpdate::setRadius(uint8_t radius)
{
    handleChange();
    this->radius = radius;
}

uint8_t IARP_LinkStateUpdate::getTTL() const
{
    return this->TTL;
}

void IARP_LinkStateUpdate::setTTL(uint8_t TTL)
{
    handleChange();
    this->TTL = TTL;
}

uint16_t IARP_LinkStateUpdate::getReserved1() const
{
    return this->reserved1;
}

void IARP_LinkStateUpdate::setReserved1(uint16_t reserved1)
{
    handleChange();
    this->reserved1 = reserved1;
}

uint8_t IARP_LinkStateUpdate::getReserved2() const
{
    return this->reserved2;
}

void IARP_LinkStateUpdate::setReserved2(uint8_t reserved2)
{
    handleChange();
    this->reserved2 = reserved2;
}

uint8_t IARP_LinkStateUpdate::getLinkDestCount() const
{
    return this->linkDestCount;
}

void IARP_LinkStateUpdate::setLinkDestCount(uint8_t linkDestCount)
{
    handleChange();
    this->linkDestCount = linkDestCount;
}

size_t IARP_LinkStateUpdate::getLinkDestDataArraySize() const
{
    return linkDestData_arraysize;
}

const IARP_LinkDestData& IARP_LinkStateUpdate::getLinkDestData(size_t k) const
{
    if (k >= linkDestData_arraysize) throw omnetpp::cRuntimeError("Array of size %lu indexed by %lu", (unsigned long)linkDestData_arraysize, (unsigned long)k);
    return this->linkDestData[k];
}

void IARP_LinkStateUpdate::setLinkDestDataArraySize(size_t newSize)
{
    handleChange();
    IARP_LinkDestData *linkDestData2 = (newSize==0) ? nullptr : new IARP_LinkDestData[newSize];
    size_t minSize = linkDestData_arraysize < newSize ? linkDestData_arraysize : newSize;
    for (size_t i = 0; i < minSize; i++)
        linkDestData2[i] = this->linkDestData[i];
    delete [] this->linkDestData;
    this->linkDestData = linkDestData2;
    linkDestData_arraysize = newSize;
}

void IARP_LinkStateUpdate::setLinkDestData(size_t k, const IARP_LinkDestData& linkDestData)
{
    if (k >= linkDestData_arraysize) throw omnetpp::cRuntimeError("Array of size %lu indexed by %lu", (unsigned long)linkDestData_arraysize, (unsigned long)k);
    handleChange();
    this->linkDestData[k] = linkDestData;
}

void IARP_LinkStateUpdate::insertLinkDestData(size_t k, const IARP_LinkDestData& linkDestData)
{
    if (k > linkDestData_arraysize) throw omnetpp::cRuntimeError("Array of size %lu indexed by %lu", (unsigned long)linkDestData_arraysize, (unsigned long)k);
    handleChange();
    size_t newSize = linkDestData_arraysize + 1;
    IARP_LinkDestData *linkDestData2 = new IARP_LinkDestData[newSize];
    size_t i;
    for (i = 0; i < k; i++)
        linkDestData2[i] = this->linkDestData[i];
    linkDestData2[k] = linkDestData;
    for (i = k + 1; i < newSize; i++)
        linkDestData2[i] = this->linkDestData[i-1];
    delete [] this->linkDestData;
    this->linkDestData = linkDestData2;
    linkDestData_arraysize = newSize;
}

void IARP_LinkStateUpdate::appendLinkDestData(const IARP_LinkDestData& linkDestData)
{
    insertLinkDestData(linkDestData_arraysize, linkDestData);
}

void IARP_LinkStateUpdate::eraseLinkDestData(size_t k)
{
    if (k >= linkDestData_arraysize) throw omnetpp::cRuntimeError("Array of size %lu indexed by %lu", (unsigned long)linkDestData_arraysize, (unsigned long)k);
    handleChange();
    size_t newSize = linkDestData_arraysize - 1;
    IARP_LinkDestData *linkDestData2 = (newSize == 0) ? nullptr : new IARP_LinkDestData[newSize];
    size_t i;
    for (i = 0; i < k; i++)
        linkDestData2[i] = this->linkDestData[i];
    for (i = k; i < newSize; i++)
        linkDestData2[i] = this->linkDestData[i+1];
    delete [] this->linkDestData;
    this->linkDestData = linkDestData2;
    linkDestData_arraysize = newSize;
}

class IARP_LinkStateUpdateDescriptor : public omnetpp::cClassDescriptor
{
  private:
    mutable const char **propertyNames;
    enum FieldConstants {
        FIELD_sourceAddr,
        FIELD_seqNum,
        FIELD_radius,
        FIELD_TTL,
        FIELD_reserved1,
        FIELD_reserved2,
        FIELD_linkDestCount,
        FIELD_linkDestData,
    };
  public:
    IARP_LinkStateUpdateDescriptor();
    virtual ~IARP_LinkStateUpdateDescriptor();

    virtual bool doesSupport(omnetpp::cObject *obj) const override;
    virtual const char **getPropertyNames() const override;
    virtual const char *getProperty(const char *propertyName) const override;
    virtual int getFieldCount() const override;
    virtual const char *getFieldName(int field) const override;
    virtual int findField(const char *fieldName) const override;
    virtual unsigned int getFieldTypeFlags(int field) const override;
    virtual const char *getFieldTypeString(int field) const override;
    virtual const char **getFieldPropertyNames(int field) const override;
    virtual const char *getFieldProperty(int field, const char *propertyName) const override;
    virtual int getFieldArraySize(omnetpp::any_ptr object, int field) const override;
    virtual void setFieldArraySize(omnetpp::any_ptr object, int field, int size) const override;

    virtual const char *getFieldDynamicTypeString(omnetpp::any_ptr object, int field, int i) const override;
    virtual std::string getFieldValueAsString(omnetpp::any_ptr object, int field, int i) const override;
    virtual void setFieldValueAsString(omnetpp::any_ptr object, int field, int i, const char *value) const override;
    virtual omnetpp::cValue getFieldValue(omnetpp::any_ptr object, int field, int i) const override;
    virtual void setFieldValue(omnetpp::any_ptr object, int field, int i, const omnetpp::cValue& value) const override;

    virtual const char *getFieldStructName(int field) const override;
    virtual omnetpp::any_ptr getFieldStructValuePointer(omnetpp::any_ptr object, int field, int i) const override;
    virtual void setFieldStructValuePointer(omnetpp::any_ptr object, int field, int i, omnetpp::any_ptr ptr) const override;
};

Register_ClassDescriptor(IARP_LinkStateUpdateDescriptor)

IARP_LinkStateUpdateDescriptor::IARP_LinkStateUpdateDescriptor() : omnetpp::cClassDescriptor(omnetpp::opp_typename(typeid(inet::zrp::IARP_LinkStateUpdate)), "inet::FieldsChunk")
{
    propertyNames = nullptr;
}

IARP_LinkStateUpdateDescriptor::~IARP_LinkStateUpdateDescriptor()
{
    delete[] propertyNames;
}

bool IARP_LinkStateUpdateDescriptor::doesSupport(omnetpp::cObject *obj) const
{
    return dynamic_cast<IARP_LinkStateUpdate *>(obj)!=nullptr;
}

const char **IARP_LinkStateUpdateDescriptor::getPropertyNames() const
{
    if (!propertyNames) {
        static const char *names[] = {  nullptr };
        omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
        const char **baseNames = base ? base->getPropertyNames() : nullptr;
        propertyNames = mergeLists(baseNames, names);
    }
    return propertyNames;
}

const char *IARP_LinkStateUpdateDescriptor::getProperty(const char *propertyName) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    return base ? base->getProperty(propertyName) : nullptr;
}

int IARP_LinkStateUpdateDescriptor::getFieldCount() const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    return base ? 8+base->getFieldCount() : 8;
}

unsigned int IARP_LinkStateUpdateDescriptor::getFieldTypeFlags(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldTypeFlags(field);
        field -= base->getFieldCount();
    }
    static unsigned int fieldTypeFlags[] = {
        0,    // FIELD_sourceAddr
        FD_ISEDITABLE,    // FIELD_seqNum
        FD_ISEDITABLE,    // FIELD_radius
        FD_ISEDITABLE,    // FIELD_TTL
        FD_ISEDITABLE,    // FIELD_reserved1
        FD_ISEDITABLE,    // FIELD_reserved2
        FD_ISEDITABLE,    // FIELD_linkDestCount
        FD_ISARRAY | FD_ISCOMPOUND | FD_ISRESIZABLE,    // FIELD_linkDestData
    };
    return (field >= 0 && field < 8) ? fieldTypeFlags[field] : 0;
}

const char *IARP_LinkStateUpdateDescriptor::getFieldName(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldName(field);
        field -= base->getFieldCount();
    }
    static const char *fieldNames[] = {
        "sourceAddr",
        "seqNum",
        "radius",
        "TTL",
        "reserved1",
        "reserved2",
        "linkDestCount",
        "linkDestData",
    };
    return (field >= 0 && field < 8) ? fieldNames[field] : nullptr;
}

int IARP_LinkStateUpdateDescriptor::findField(const char *fieldName) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    int baseIndex = base ? base->getFieldCount() : 0;
    if (strcmp(fieldName, "sourceAddr") == 0) return baseIndex + 0;
    if (strcmp(fieldName, "seqNum") == 0) return baseIndex + 1;
    if (strcmp(fieldName, "radius") == 0) return baseIndex + 2;
    if (strcmp(fieldName, "TTL") == 0) return baseIndex + 3;
    if (strcmp(fieldName, "reserved1") == 0) return baseIndex + 4;
    if (strcmp(fieldName, "reserved2") == 0) return baseIndex + 5;
    if (strcmp(fieldName, "linkDestCount") == 0) return baseIndex + 6;
    if (strcmp(fieldName, "linkDestData") == 0) return baseIndex + 7;
    return base ? base->findField(fieldName) : -1;
}

const char *IARP_LinkStateUpdateDescriptor::getFieldTypeString(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldTypeString(field);
        field -= base->getFieldCount();
    }
    static const char *fieldTypeStrings[] = {
        "inet::L3Address",    // FIELD_sourceAddr
        "uint16_t",    // FIELD_seqNum
        "uint8_t",    // FIELD_radius
        "uint8_t",    // FIELD_TTL
        "uint16_t",    // FIELD_reserved1
        "uint8_t",    // FIELD_reserved2
        "uint8_t",    // FIELD_linkDestCount
        "inet::zrp::IARP_LinkDestData",    // FIELD_linkDestData
    };
    return (field >= 0 && field < 8) ? fieldTypeStrings[field] : nullptr;
}

const char **IARP_LinkStateUpdateDescriptor::getFieldPropertyNames(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldPropertyNames(field);
        field -= base->getFieldCount();
    }
    switch (field) {
        default: return nullptr;
    }
}

const char *IARP_LinkStateUpdateDescriptor::getFieldProperty(int field, const char *propertyName) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldProperty(field, propertyName);
        field -= base->getFieldCount();
    }
    switch (field) {
        default: return nullptr;
    }
}

int IARP_LinkStateUpdateDescriptor::getFieldArraySize(omnetpp::any_ptr object, int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldArraySize(object, field);
        field -= base->getFieldCount();
    }
    IARP_LinkStateUpdate *pp = omnetpp::fromAnyPtr<IARP_LinkStateUpdate>(object); (void)pp;
    switch (field) {
        case FIELD_linkDestData: return pp->getLinkDestDataArraySize();
        default: return 0;
    }
}

void IARP_LinkStateUpdateDescriptor::setFieldArraySize(omnetpp::any_ptr object, int field, int size) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldArraySize(object, field, size);
            return;
        }
        field -= base->getFieldCount();
    }
    IARP_LinkStateUpdate *pp = omnetpp::fromAnyPtr<IARP_LinkStateUpdate>(object); (void)pp;
    switch (field) {
        case FIELD_linkDestData: pp->setLinkDestDataArraySize(size); break;
        default: throw omnetpp::cRuntimeError("Cannot set array size of field %d of class 'IARP_LinkStateUpdate'", field);
    }
}

const char *IARP_LinkStateUpdateDescriptor::getFieldDynamicTypeString(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldDynamicTypeString(object,field,i);
        field -= base->getFieldCount();
    }
    IARP_LinkStateUpdate *pp = omnetpp::fromAnyPtr<IARP_LinkStateUpdate>(object); (void)pp;
    switch (field) {
        default: return nullptr;
    }
}

std::string IARP_LinkStateUpdateDescriptor::getFieldValueAsString(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldValueAsString(object,field,i);
        field -= base->getFieldCount();
    }
    IARP_LinkStateUpdate *pp = omnetpp::fromAnyPtr<IARP_LinkStateUpdate>(object); (void)pp;
    switch (field) {
        case FIELD_sourceAddr: return pp->getSourceAddr().str();
        case FIELD_seqNum: return ulong2string(pp->getSeqNum());
        case FIELD_radius: return ulong2string(pp->getRadius());
        case FIELD_TTL: return ulong2string(pp->getTTL());
        case FIELD_reserved1: return ulong2string(pp->getReserved1());
        case FIELD_reserved2: return ulong2string(pp->getReserved2());
        case FIELD_linkDestCount: return ulong2string(pp->getLinkDestCount());
        case FIELD_linkDestData: return "";
        default: return "";
    }
}

void IARP_LinkStateUpdateDescriptor::setFieldValueAsString(omnetpp::any_ptr object, int field, int i, const char *value) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldValueAsString(object, field, i, value);
            return;
        }
        field -= base->getFieldCount();
    }
    IARP_LinkStateUpdate *pp = omnetpp::fromAnyPtr<IARP_LinkStateUpdate>(object); (void)pp;
    switch (field) {
        case FIELD_seqNum: pp->setSeqNum(string2ulong(value)); break;
        case FIELD_radius: pp->setRadius(string2ulong(value)); break;
        case FIELD_TTL: pp->setTTL(string2ulong(value)); break;
        case FIELD_reserved1: pp->setReserved1(string2ulong(value)); break;
        case FIELD_reserved2: pp->setReserved2(string2ulong(value)); break;
        case FIELD_linkDestCount: pp->setLinkDestCount(string2ulong(value)); break;
        default: throw omnetpp::cRuntimeError("Cannot set field %d of class 'IARP_LinkStateUpdate'", field);
    }
}

omnetpp::cValue IARP_LinkStateUpdateDescriptor::getFieldValue(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldValue(object,field,i);
        field -= base->getFieldCount();
    }
    IARP_LinkStateUpdate *pp = omnetpp::fromAnyPtr<IARP_LinkStateUpdate>(object); (void)pp;
    switch (field) {
        case FIELD_sourceAddr: return omnetpp::toAnyPtr(&pp->getSourceAddr()); break;
        case FIELD_seqNum: return (omnetpp::intval_t)(pp->getSeqNum());
        case FIELD_radius: return (omnetpp::intval_t)(pp->getRadius());
        case FIELD_TTL: return (omnetpp::intval_t)(pp->getTTL());
        case FIELD_reserved1: return (omnetpp::intval_t)(pp->getReserved1());
        case FIELD_reserved2: return (omnetpp::intval_t)(pp->getReserved2());
        case FIELD_linkDestCount: return (omnetpp::intval_t)(pp->getLinkDestCount());
        case FIELD_linkDestData: return omnetpp::toAnyPtr(&pp->getLinkDestData(i)); break;
        default: throw omnetpp::cRuntimeError("Cannot return field %d of class 'IARP_LinkStateUpdate' as cValue -- field index out of range?", field);
    }
}

void IARP_LinkStateUpdateDescriptor::setFieldValue(omnetpp::any_ptr object, int field, int i, const omnetpp::cValue& value) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldValue(object, field, i, value);
            return;
        }
        field -= base->getFieldCount();
    }
    IARP_LinkStateUpdate *pp = omnetpp::fromAnyPtr<IARP_LinkStateUpdate>(object); (void)pp;
    switch (field) {
        case FIELD_seqNum: pp->setSeqNum(omnetpp::checked_int_cast<uint16_t>(value.intValue())); break;
        case FIELD_radius: pp->setRadius(omnetpp::checked_int_cast<uint8_t>(value.intValue())); break;
        case FIELD_TTL: pp->setTTL(omnetpp::checked_int_cast<uint8_t>(value.intValue())); break;
        case FIELD_reserved1: pp->setReserved1(omnetpp::checked_int_cast<uint16_t>(value.intValue())); break;
        case FIELD_reserved2: pp->setReserved2(omnetpp::checked_int_cast<uint8_t>(value.intValue())); break;
        case FIELD_linkDestCount: pp->setLinkDestCount(omnetpp::checked_int_cast<uint8_t>(value.intValue())); break;
        default: throw omnetpp::cRuntimeError("Cannot set field %d of class 'IARP_LinkStateUpdate'", field);
    }
}

const char *IARP_LinkStateUpdateDescriptor::getFieldStructName(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldStructName(field);
        field -= base->getFieldCount();
    }
    switch (field) {
        case FIELD_linkDestData: return omnetpp::opp_typename(typeid(IARP_LinkDestData));
        default: return nullptr;
    };
}

omnetpp::any_ptr IARP_LinkStateUpdateDescriptor::getFieldStructValuePointer(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldStructValuePointer(object, field, i);
        field -= base->getFieldCount();
    }
    IARP_LinkStateUpdate *pp = omnetpp::fromAnyPtr<IARP_LinkStateUpdate>(object); (void)pp;
    switch (field) {
        case FIELD_sourceAddr: return omnetpp::toAnyPtr(&pp->getSourceAddr()); break;
        case FIELD_linkDestData: return omnetpp::toAnyPtr(&pp->getLinkDestData(i)); break;
        default: return omnetpp::any_ptr(nullptr);
    }
}

void IARP_LinkStateUpdateDescriptor::setFieldStructValuePointer(omnetpp::any_ptr object, int field, int i, omnetpp::any_ptr ptr) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldStructValuePointer(object, field, i, ptr);
            return;
        }
        field -= base->getFieldCount();
    }
    IARP_LinkStateUpdate *pp = omnetpp::fromAnyPtr<IARP_LinkStateUpdate>(object); (void)pp;
    switch (field) {
        default: throw omnetpp::cRuntimeError("Cannot set field %d of class 'IARP_LinkStateUpdate'", field);
    }
}

}  // namespace zrp
}  // namespace inet

namespace omnetpp {

}  // namespace omnetpp

