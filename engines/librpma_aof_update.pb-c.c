/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: librpma_aof_update.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "librpma_aof_update.pb-c.h"
void   aof_update_request__init
                     (AOFUpdateRequest         *message)
{
  static const AOFUpdateRequest init_value = AOF_UPDATE_REQUEST__INIT;
  *message = init_value;
}
size_t aof_update_request__get_packed_size
                     (const AOFUpdateRequest *message)
{
  assert(message->base.descriptor == &aof_update_request__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t aof_update_request__pack
                     (const AOFUpdateRequest *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &aof_update_request__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t aof_update_request__pack_to_buffer
                     (const AOFUpdateRequest *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &aof_update_request__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
AOFUpdateRequest *
       aof_update_request__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (AOFUpdateRequest *)
     protobuf_c_message_unpack (&aof_update_request__descriptor,
                                allocator, len, data);
}
void   aof_update_request__free_unpacked
                     (AOFUpdateRequest *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &aof_update_request__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   aof_update_response__init
                     (AOFUpdateResponse         *message)
{
  static const AOFUpdateResponse init_value = AOF_UPDATE_RESPONSE__INIT;
  *message = init_value;
}
size_t aof_update_response__get_packed_size
                     (const AOFUpdateResponse *message)
{
  assert(message->base.descriptor == &aof_update_response__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t aof_update_response__pack
                     (const AOFUpdateResponse *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &aof_update_response__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t aof_update_response__pack_to_buffer
                     (const AOFUpdateResponse *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &aof_update_response__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
AOFUpdateResponse *
       aof_update_response__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (AOFUpdateResponse *)
     protobuf_c_message_unpack (&aof_update_response__descriptor,
                                allocator, len, data);
}
void   aof_update_response__free_unpacked
                     (AOFUpdateResponse *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &aof_update_response__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor aof_update_request__field_descriptors[4] =
{
  {
    "append_offset",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_FIXED64,
    0,   /* quantifier_offset */
    offsetof(AOFUpdateRequest, append_offset),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "append_length",
    2,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_FIXED64,
    0,   /* quantifier_offset */
    offsetof(AOFUpdateRequest, append_length),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "pointer_offset",
    3,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_FIXED64,
    0,   /* quantifier_offset */
    offsetof(AOFUpdateRequest, pointer_offset),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "op_context",
    4,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_FIXED64,
    0,   /* quantifier_offset */
    offsetof(AOFUpdateRequest, op_context),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned aof_update_request__field_indices_by_name[] = {
  1,   /* field[1] = append_length */
  0,   /* field[0] = append_offset */
  3,   /* field[3] = op_context */
  2,   /* field[2] = pointer_offset */
};
static const ProtobufCIntRange aof_update_request__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 4 }
};
const ProtobufCMessageDescriptor aof_update_request__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "AOF_update_request",
  "AOFUpdateRequest",
  "AOFUpdateRequest",
  "",
  sizeof(AOFUpdateRequest),
  4,
  aof_update_request__field_descriptors,
  aof_update_request__field_indices_by_name,
  1,  aof_update_request__number_ranges,
  (ProtobufCMessageInit) aof_update_request__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor aof_update_response__field_descriptors[1] =
{
  {
    "op_context",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_FIXED64,
    0,   /* quantifier_offset */
    offsetof(AOFUpdateResponse, op_context),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned aof_update_response__field_indices_by_name[] = {
  0,   /* field[0] = op_context */
};
static const ProtobufCIntRange aof_update_response__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor aof_update_response__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "AOF_update_response",
  "AOFUpdateResponse",
  "AOFUpdateResponse",
  "",
  sizeof(AOFUpdateResponse),
  1,
  aof_update_response__field_descriptors,
  aof_update_response__field_indices_by_name,
  1,  aof_update_response__number_ranges,
  (ProtobufCMessageInit) aof_update_response__init,
  NULL,NULL,NULL    /* reserved[123] */
};
