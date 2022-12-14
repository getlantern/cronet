# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: build/android/pylib/local/emulator/proto/avd.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='build/android/pylib/local/emulator/proto/avd.proto',
  package='tools.android.avd.proto',
  syntax='proto3',
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n2build/android/pylib/local/emulator/proto/avd.proto\x12\x17tools.android.avd.proto\"G\n\x0b\x43IPDPackage\x12\x14\n\x0cpackage_name\x18\x01 \x01(\t\x12\x0f\n\x07version\x18\x02 \x01(\t\x12\x11\n\tdest_path\x18\x03 \x01(\t\"@\n\x0eScreenSettings\x12\x0e\n\x06height\x18\x01 \x01(\r\x12\r\n\x05width\x18\x02 \x01(\r\x12\x0f\n\x07\x64\x65nsity\x18\x03 \x01(\r\"\x1e\n\x0eSdcardSettings\x12\x0c\n\x04size\x18\x01 \x01(\t\"\xa8\x03\n\x0b\x41vdSettings\x12\x37\n\x06screen\x18\x01 \x01(\x0b\x32\'.tools.android.avd.proto.ScreenSettings\x12\x37\n\x06sdcard\x18\x02 \x01(\x0b\x32\'.tools.android.avd.proto.SdcardSettings\x12U\n\x11\x61\x64vanced_features\x18\x03 \x03(\x0b\x32:.tools.android.avd.proto.AvdSettings.AdvancedFeaturesEntry\x12\x10\n\x08ram_size\x18\x04 \x01(\r\x12O\n\x0e\x61vd_properties\x18\x05 \x03(\x0b\x32\x37.tools.android.avd.proto.AvdSettings.AvdPropertiesEntry\x1a\x37\n\x15\x41\x64vancedFeaturesEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x34\n\x12\x41vdPropertiesEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xe4\x03\n\x03\x41vd\x12>\n\x10\x65mulator_package\x18\x01 \x01(\x0b\x32$.tools.android.avd.proto.CIPDPackage\x12\x42\n\x14system_image_package\x18\x02 \x01(\x0b\x32$.tools.android.avd.proto.CIPDPackage\x12\x19\n\x11system_image_name\x18\x03 \x01(\t\x12\x39\n\x0b\x61vd_package\x18\x04 \x01(\x0b\x32$.tools.android.avd.proto.CIPDPackage\x12\x10\n\x08\x61vd_name\x18\x05 \x01(\t\x12:\n\x0c\x61vd_settings\x18\x06 \x01(\x0b\x32$.tools.android.avd.proto.AvdSettings\x12\x0f\n\x07min_sdk\x18\x07 \x01(\r\x12(\n install_privileged_apk_partition\x18\x08 \x01(\t\x12<\n\x0eprivileged_apk\x18\t \x03(\x0b\x32$.tools.android.avd.proto.CIPDPackage\x12<\n\x0e\x61\x64\x64itional_apk\x18\n \x03(\x0b\x32$.tools.android.avd.proto.CIPDPackageb\x06proto3'
)




_CIPDPACKAGE = _descriptor.Descriptor(
  name='CIPDPackage',
  full_name='tools.android.avd.proto.CIPDPackage',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='package_name', full_name='tools.android.avd.proto.CIPDPackage.package_name', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='version', full_name='tools.android.avd.proto.CIPDPackage.version', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='dest_path', full_name='tools.android.avd.proto.CIPDPackage.dest_path', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=79,
  serialized_end=150,
)


_SCREENSETTINGS = _descriptor.Descriptor(
  name='ScreenSettings',
  full_name='tools.android.avd.proto.ScreenSettings',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='height', full_name='tools.android.avd.proto.ScreenSettings.height', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='width', full_name='tools.android.avd.proto.ScreenSettings.width', index=1,
      number=2, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='density', full_name='tools.android.avd.proto.ScreenSettings.density', index=2,
      number=3, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=152,
  serialized_end=216,
)


_SDCARDSETTINGS = _descriptor.Descriptor(
  name='SdcardSettings',
  full_name='tools.android.avd.proto.SdcardSettings',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='size', full_name='tools.android.avd.proto.SdcardSettings.size', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=218,
  serialized_end=248,
)


_AVDSETTINGS_ADVANCEDFEATURESENTRY = _descriptor.Descriptor(
  name='AdvancedFeaturesEntry',
  full_name='tools.android.avd.proto.AvdSettings.AdvancedFeaturesEntry',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='key', full_name='tools.android.avd.proto.AvdSettings.AdvancedFeaturesEntry.key', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='value', full_name='tools.android.avd.proto.AvdSettings.AdvancedFeaturesEntry.value', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=b'8\001',
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=566,
  serialized_end=621,
)

_AVDSETTINGS_AVDPROPERTIESENTRY = _descriptor.Descriptor(
  name='AvdPropertiesEntry',
  full_name='tools.android.avd.proto.AvdSettings.AvdPropertiesEntry',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='key', full_name='tools.android.avd.proto.AvdSettings.AvdPropertiesEntry.key', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='value', full_name='tools.android.avd.proto.AvdSettings.AvdPropertiesEntry.value', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=b'8\001',
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=623,
  serialized_end=675,
)

_AVDSETTINGS = _descriptor.Descriptor(
  name='AvdSettings',
  full_name='tools.android.avd.proto.AvdSettings',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='screen', full_name='tools.android.avd.proto.AvdSettings.screen', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='sdcard', full_name='tools.android.avd.proto.AvdSettings.sdcard', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='advanced_features', full_name='tools.android.avd.proto.AvdSettings.advanced_features', index=2,
      number=3, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='ram_size', full_name='tools.android.avd.proto.AvdSettings.ram_size', index=3,
      number=4, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='avd_properties', full_name='tools.android.avd.proto.AvdSettings.avd_properties', index=4,
      number=5, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[_AVDSETTINGS_ADVANCEDFEATURESENTRY, _AVDSETTINGS_AVDPROPERTIESENTRY, ],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=251,
  serialized_end=675,
)


_AVD = _descriptor.Descriptor(
  name='Avd',
  full_name='tools.android.avd.proto.Avd',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='emulator_package', full_name='tools.android.avd.proto.Avd.emulator_package', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='system_image_package', full_name='tools.android.avd.proto.Avd.system_image_package', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='system_image_name', full_name='tools.android.avd.proto.Avd.system_image_name', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='avd_package', full_name='tools.android.avd.proto.Avd.avd_package', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='avd_name', full_name='tools.android.avd.proto.Avd.avd_name', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='avd_settings', full_name='tools.android.avd.proto.Avd.avd_settings', index=5,
      number=6, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='min_sdk', full_name='tools.android.avd.proto.Avd.min_sdk', index=6,
      number=7, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='install_privileged_apk_partition', full_name='tools.android.avd.proto.Avd.install_privileged_apk_partition', index=7,
      number=8, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='privileged_apk', full_name='tools.android.avd.proto.Avd.privileged_apk', index=8,
      number=9, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='additional_apk', full_name='tools.android.avd.proto.Avd.additional_apk', index=9,
      number=10, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=678,
  serialized_end=1162,
)

_AVDSETTINGS_ADVANCEDFEATURESENTRY.containing_type = _AVDSETTINGS
_AVDSETTINGS_AVDPROPERTIESENTRY.containing_type = _AVDSETTINGS
_AVDSETTINGS.fields_by_name['screen'].message_type = _SCREENSETTINGS
_AVDSETTINGS.fields_by_name['sdcard'].message_type = _SDCARDSETTINGS
_AVDSETTINGS.fields_by_name['advanced_features'].message_type = _AVDSETTINGS_ADVANCEDFEATURESENTRY
_AVDSETTINGS.fields_by_name['avd_properties'].message_type = _AVDSETTINGS_AVDPROPERTIESENTRY
_AVD.fields_by_name['emulator_package'].message_type = _CIPDPACKAGE
_AVD.fields_by_name['system_image_package'].message_type = _CIPDPACKAGE
_AVD.fields_by_name['avd_package'].message_type = _CIPDPACKAGE
_AVD.fields_by_name['avd_settings'].message_type = _AVDSETTINGS
_AVD.fields_by_name['privileged_apk'].message_type = _CIPDPACKAGE
_AVD.fields_by_name['additional_apk'].message_type = _CIPDPACKAGE
DESCRIPTOR.message_types_by_name['CIPDPackage'] = _CIPDPACKAGE
DESCRIPTOR.message_types_by_name['ScreenSettings'] = _SCREENSETTINGS
DESCRIPTOR.message_types_by_name['SdcardSettings'] = _SDCARDSETTINGS
DESCRIPTOR.message_types_by_name['AvdSettings'] = _AVDSETTINGS
DESCRIPTOR.message_types_by_name['Avd'] = _AVD
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

CIPDPackage = _reflection.GeneratedProtocolMessageType('CIPDPackage', (_message.Message,), {
  'DESCRIPTOR' : _CIPDPACKAGE,
  '__module__' : 'build.android.pylib.local.emulator.proto.avd_pb2'
  # @@protoc_insertion_point(class_scope:tools.android.avd.proto.CIPDPackage)
  })
_sym_db.RegisterMessage(CIPDPackage)

ScreenSettings = _reflection.GeneratedProtocolMessageType('ScreenSettings', (_message.Message,), {
  'DESCRIPTOR' : _SCREENSETTINGS,
  '__module__' : 'build.android.pylib.local.emulator.proto.avd_pb2'
  # @@protoc_insertion_point(class_scope:tools.android.avd.proto.ScreenSettings)
  })
_sym_db.RegisterMessage(ScreenSettings)

SdcardSettings = _reflection.GeneratedProtocolMessageType('SdcardSettings', (_message.Message,), {
  'DESCRIPTOR' : _SDCARDSETTINGS,
  '__module__' : 'build.android.pylib.local.emulator.proto.avd_pb2'
  # @@protoc_insertion_point(class_scope:tools.android.avd.proto.SdcardSettings)
  })
_sym_db.RegisterMessage(SdcardSettings)

AvdSettings = _reflection.GeneratedProtocolMessageType('AvdSettings', (_message.Message,), {

  'AdvancedFeaturesEntry' : _reflection.GeneratedProtocolMessageType('AdvancedFeaturesEntry', (_message.Message,), {
    'DESCRIPTOR' : _AVDSETTINGS_ADVANCEDFEATURESENTRY,
    '__module__' : 'build.android.pylib.local.emulator.proto.avd_pb2'
    # @@protoc_insertion_point(class_scope:tools.android.avd.proto.AvdSettings.AdvancedFeaturesEntry)
    })
  ,

  'AvdPropertiesEntry' : _reflection.GeneratedProtocolMessageType('AvdPropertiesEntry', (_message.Message,), {
    'DESCRIPTOR' : _AVDSETTINGS_AVDPROPERTIESENTRY,
    '__module__' : 'build.android.pylib.local.emulator.proto.avd_pb2'
    # @@protoc_insertion_point(class_scope:tools.android.avd.proto.AvdSettings.AvdPropertiesEntry)
    })
  ,
  'DESCRIPTOR' : _AVDSETTINGS,
  '__module__' : 'build.android.pylib.local.emulator.proto.avd_pb2'
  # @@protoc_insertion_point(class_scope:tools.android.avd.proto.AvdSettings)
  })
_sym_db.RegisterMessage(AvdSettings)
_sym_db.RegisterMessage(AvdSettings.AdvancedFeaturesEntry)
_sym_db.RegisterMessage(AvdSettings.AvdPropertiesEntry)

Avd = _reflection.GeneratedProtocolMessageType('Avd', (_message.Message,), {
  'DESCRIPTOR' : _AVD,
  '__module__' : 'build.android.pylib.local.emulator.proto.avd_pb2'
  # @@protoc_insertion_point(class_scope:tools.android.avd.proto.Avd)
  })
_sym_db.RegisterMessage(Avd)


_AVDSETTINGS_ADVANCEDFEATURESENTRY._options = None
_AVDSETTINGS_AVDPROPERTIESENTRY._options = None
# @@protoc_insertion_point(module_scope)
