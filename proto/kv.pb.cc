// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: kv.proto

#include "kv.pb.h"

#include <algorithm>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/wire_format_lite.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>

PROTOBUF_PRAGMA_INIT_SEG

namespace _pb = ::PROTOBUF_NAMESPACE_ID;
namespace _pbi = _pb::internal;

PROTOBUF_CONSTEXPR KeyValue::KeyValue(
    ::_pbi::ConstantInitialized): _impl_{
    /*decltype(_impl_.key_)*/{&::_pbi::fixed_address_empty_string, ::_pbi::ConstantInitialized{}}
  , /*decltype(_impl_.value_)*/{&::_pbi::fixed_address_empty_string, ::_pbi::ConstantInitialized{}}
  , /*decltype(_impl_._cached_size_)*/{}} {}
struct KeyValueDefaultTypeInternal {
  PROTOBUF_CONSTEXPR KeyValueDefaultTypeInternal()
      : _instance(::_pbi::ConstantInitialized{}) {}
  ~KeyValueDefaultTypeInternal() {}
  union {
    KeyValue _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT PROTOBUF_ATTRIBUTE_INIT_PRIORITY1 KeyValueDefaultTypeInternal _KeyValue_default_instance_;
static ::_pb::Metadata file_level_metadata_kv_2eproto[1];
static constexpr ::_pb::EnumDescriptor const** file_level_enum_descriptors_kv_2eproto = nullptr;
static constexpr ::_pb::ServiceDescriptor const** file_level_service_descriptors_kv_2eproto = nullptr;

const uint32_t TableStruct_kv_2eproto::offsets[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::KeyValue, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  ~0u,  // no _inlined_string_donated_
  PROTOBUF_FIELD_OFFSET(::KeyValue, _impl_.key_),
  PROTOBUF_FIELD_OFFSET(::KeyValue, _impl_.value_),
};
static const ::_pbi::MigrationSchema schemas[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  { 0, -1, -1, sizeof(::KeyValue)},
};

static const ::_pb::Message* const file_default_instances[] = {
  &::_KeyValue_default_instance_._instance,
};

const char descriptor_table_protodef_kv_2eproto[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) =
  "\n\010kv.proto\"&\n\010KeyValue\022\013\n\003key\030\001 \001(\014\022\r\n\005v"
  "alue\030\002 \001(\014b\006proto3"
  ;
static ::_pbi::once_flag descriptor_table_kv_2eproto_once;
const ::_pbi::DescriptorTable descriptor_table_kv_2eproto = {
    false, false, 58, descriptor_table_protodef_kv_2eproto,
    "kv.proto",
    &descriptor_table_kv_2eproto_once, nullptr, 0, 1,
    schemas, file_default_instances, TableStruct_kv_2eproto::offsets,
    file_level_metadata_kv_2eproto, file_level_enum_descriptors_kv_2eproto,
    file_level_service_descriptors_kv_2eproto,
};
PROTOBUF_ATTRIBUTE_WEAK const ::_pbi::DescriptorTable* descriptor_table_kv_2eproto_getter() {
  return &descriptor_table_kv_2eproto;
}

// Force running AddDescriptors() at dynamic initialization time.
PROTOBUF_ATTRIBUTE_INIT_PRIORITY2 static ::_pbi::AddDescriptorsRunner dynamic_init_dummy_kv_2eproto(&descriptor_table_kv_2eproto);

// ===================================================================

class KeyValue::_Internal {
 public:
};

KeyValue::KeyValue(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena, is_message_owned) {
  SharedCtor(arena, is_message_owned);
  // @@protoc_insertion_point(arena_constructor:KeyValue)
}
KeyValue::KeyValue(const KeyValue& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  KeyValue* const _this = this; (void)_this;
  new (&_impl_) Impl_{
      decltype(_impl_.key_){}
    , decltype(_impl_.value_){}
    , /*decltype(_impl_._cached_size_)*/{}};

  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  _impl_.key_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.key_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (!from._internal_key().empty()) {
    _this->_impl_.key_.Set(from._internal_key(), 
      _this->GetArenaForAllocation());
  }
  _impl_.value_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.value_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (!from._internal_value().empty()) {
    _this->_impl_.value_.Set(from._internal_value(), 
      _this->GetArenaForAllocation());
  }
  // @@protoc_insertion_point(copy_constructor:KeyValue)
}

inline void KeyValue::SharedCtor(
    ::_pb::Arena* arena, bool is_message_owned) {
  (void)arena;
  (void)is_message_owned;
  new (&_impl_) Impl_{
      decltype(_impl_.key_){}
    , decltype(_impl_.value_){}
    , /*decltype(_impl_._cached_size_)*/{}
  };
  _impl_.key_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.key_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  _impl_.value_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.value_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
}

KeyValue::~KeyValue() {
  // @@protoc_insertion_point(destructor:KeyValue)
  if (auto *arena = _internal_metadata_.DeleteReturnArena<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>()) {
  (void)arena;
    return;
  }
  SharedDtor();
}

inline void KeyValue::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  _impl_.key_.Destroy();
  _impl_.value_.Destroy();
}

void KeyValue::SetCachedSize(int size) const {
  _impl_._cached_size_.Set(size);
}

void KeyValue::Clear() {
// @@protoc_insertion_point(message_clear_start:KeyValue)
  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  _impl_.key_.ClearToEmpty();
  _impl_.value_.ClearToEmpty();
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* KeyValue::_InternalParse(const char* ptr, ::_pbi::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    uint32_t tag;
    ptr = ::_pbi::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // bytes key = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 10)) {
          auto str = _internal_mutable_key();
          ptr = ::_pbi::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      // bytes value = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 18)) {
          auto str = _internal_mutable_value();
          ptr = ::_pbi::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      default:
        goto handle_unusual;
    }  // switch
  handle_unusual:
    if ((tag == 0) || ((tag & 7) == 4)) {
      CHK_(ptr);
      ctx->SetLastTag(tag);
      goto message_done;
    }
    ptr = UnknownFieldParse(
        tag,
        _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
        ptr, ctx);
    CHK_(ptr != nullptr);
  }  // while
message_done:
  return ptr;
failure:
  ptr = nullptr;
  goto message_done;
#undef CHK_
}

uint8_t* KeyValue::_InternalSerialize(
    uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:KeyValue)
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  // bytes key = 1;
  if (!this->_internal_key().empty()) {
    target = stream->WriteBytesMaybeAliased(
        1, this->_internal_key(), target);
  }

  // bytes value = 2;
  if (!this->_internal_value().empty()) {
    target = stream->WriteBytesMaybeAliased(
        2, this->_internal_value(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::_pbi::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:KeyValue)
  return target;
}

size_t KeyValue::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:KeyValue)
  size_t total_size = 0;

  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // bytes key = 1;
  if (!this->_internal_key().empty()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
        this->_internal_key());
  }

  // bytes value = 2;
  if (!this->_internal_value().empty()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
        this->_internal_value());
  }

  return MaybeComputeUnknownFieldsSize(total_size, &_impl_._cached_size_);
}

const ::PROTOBUF_NAMESPACE_ID::Message::ClassData KeyValue::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::Message::CopyWithSourceCheck,
    KeyValue::MergeImpl
};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*KeyValue::GetClassData() const { return &_class_data_; }


void KeyValue::MergeImpl(::PROTOBUF_NAMESPACE_ID::Message& to_msg, const ::PROTOBUF_NAMESPACE_ID::Message& from_msg) {
  auto* const _this = static_cast<KeyValue*>(&to_msg);
  auto& from = static_cast<const KeyValue&>(from_msg);
  // @@protoc_insertion_point(class_specific_merge_from_start:KeyValue)
  GOOGLE_DCHECK_NE(&from, _this);
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  if (!from._internal_key().empty()) {
    _this->_internal_set_key(from._internal_key());
  }
  if (!from._internal_value().empty()) {
    _this->_internal_set_value(from._internal_value());
  }
  _this->_internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
}

void KeyValue::CopyFrom(const KeyValue& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:KeyValue)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool KeyValue::IsInitialized() const {
  return true;
}

void KeyValue::InternalSwap(KeyValue* other) {
  using std::swap;
  auto* lhs_arena = GetArenaForAllocation();
  auto* rhs_arena = other->GetArenaForAllocation();
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &_impl_.key_, lhs_arena,
      &other->_impl_.key_, rhs_arena
  );
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &_impl_.value_, lhs_arena,
      &other->_impl_.value_, rhs_arena
  );
}

::PROTOBUF_NAMESPACE_ID::Metadata KeyValue::GetMetadata() const {
  return ::_pbi::AssignDescriptors(
      &descriptor_table_kv_2eproto_getter, &descriptor_table_kv_2eproto_once,
      file_level_metadata_kv_2eproto[0]);
}

// @@protoc_insertion_point(namespace_scope)
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::KeyValue*
Arena::CreateMaybeMessage< ::KeyValue >(Arena* arena) {
  return Arena::CreateMessageInternal< ::KeyValue >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>
