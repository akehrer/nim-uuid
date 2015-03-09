# Copyright (C) 2014 Erwan Ameil - MIT license (see LICENSE file)
# Original C header licence follows

#
#  Public include file for the UUID library
# 
#  Copyright (C) 1996, 1997, 1998 Theodore Ts'o.
# 
#  %Begin-Header%
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#  1. Redistributions of source code must retain the above copyright
#     notice, and the entire permission notice in its entirety,
#     including the disclaimer of warranties.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  3. The name of the author may not be used to endorse or promote
#     products derived from this software without specific prior
#     written permission.
# 
#  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
#  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
#  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
#  WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
#  OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
#  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
#  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
#  USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
#  DAMAGE.
#  %End-Header%
# 

import algorithm, strutils, times, unsigned

{.deadCodeElim: on.}

type 
  Tuuid* = array[16, uint8] 
  UUIDError = object of Exception

# UUID Variant definitions 

const 
  UUID_VARIANT_NCS* = 0
  UUID_VARIANT_DCE* = 1
  UUID_VARIANT_MICROSOFT* = 2
  UUID_VARIANT_OTHER* = 3

# UUID Type definitions 

const 
  UUID_TYPE_DCE_TIME* = 1
  UUID_TYPE_DCE_RANDOM* = 4

# ####################################################################### #
#                 Helpers for working with Tuuid types
# ####################################################################### #
# Forward declarations
proc uuid_compare*(uu1, uu2: Tuuid): int

proc toHex*(uu: Tuuid): string = 
  result = ""
  for c in uu:
    result.add strutils.toHex(int(c), 2)

proc `$`*(uu: Tuuid): string =
    var hex = uu.toHex()
    return toLower("$1-$2-$3-$4-$5" % [hex[0..7], hex[8..11], hex[12..15],
                                       hex[16..19], hex[20..31]] )

proc `==`*(uu1, uu2: Tuuid): bool = 
  var res = uuid_compare(uu1, uu2)
  if res == 0:
    result = true
  else:
    result = false

proc `>`*(uu1, uu2: Tuuid): bool = 
  var res = uuid_compare(uu1, uu2)
  if res == 1:
    result = true
  else:
    result = false

proc `<`*(uu1, uu2: Tuuid): bool = 
  var res = uuid_compare(uu1, uu2)
  if res == -1:
    result = true
  else:
    result = false

proc getTimeLow*(uu: Tuuid): int =
  for c in uu[0..3]:
    result = result shl 8
    result += int(c)

proc getTimeMid*(uu: Tuuid): int = 
  for c in uu[4..5]:
    result = result shl 8
    result += int(c)

proc getTimeHiVersion*(uu: Tuuid): int = 
  for c in uu[6..7]:
    result = result shl 8
    result += int(c)

proc getClockHiVariant*(uu: Tuuid): int = 
  result = int(uu[8])

proc getClockLow*(uu: Tuuid): int = 
  result = int(uu[9])

proc getNode*(uu: Tuuid): int64 = 
  for c in uu[10..15]:
    result = result shl 8
    result += int(c)

proc getTime*(uu: Tuuid): int64 = 
  # 100-ns intervals since UUID epoch 1582-10-15 00:00:00
  result = ((int64(getTimeHiVersion(uu) and 0x0fff) shl 48) + 
           (int64(getTimeMid(uu)) shl 32) + int64(getTimeLow(uu)))

proc getUnixTime*(uu: Tuuid): float = 
  # Thanks to uuid.py for this:
  # 0x01b21dd213814000 is the number of 100-ns intervals between the
  # UUID epoch 1582-10-15 00:00:00 and the Unix epoch 1970-01-01 00:00:00.
  var timestamp = uu.getTime()
  result = ((float(timestamp - 0x01b21dd213814000) * 100.0) / 1e9)

proc getVariant*(uu: Tuuid): int =
  case int(uu.getClockHiVariant() and 0xf0) div 15
  of 8: result = UUID_VARIANT_NCS
  of 9: result = UUID_VARIANT_DCE
  of 10: result = UUID_VARIANT_MICROSOFT
  else: result = UUID_VARIANT_OTHER

proc getVersion*(uu: Tuuid): int =
  result = int(uu.getTimeHiVersion() and 0xf000) div 4095
  if result > 4 or result < 1:
    raise newException(UUIDError, "Unspecified version value '" & $result & "'")

# uuid_compare is a reimplementation of the example in RFC4122 since Windows
# treats UUIDs differently internally.  (See note in uuid_parse)
template CHECK(f1, f2: expr): expr =
  if (f1 != f2):
    if f1 > f2:
      return 1
    else:
      return -1
  else:
    return 0

proc uuid_compare*(uu1, uu2: Tuuid): int =
  CHECK(uu1.getTimeLow(), uu2.getTimeLow())
  CHECK(uu1.getTimeMid(), uu2.getTimeMid())
  CHECK(uu1.getTimeHiVersion(), uu2.getTimeHiVersion())
  CHECK(uu1.getClockHiVariant(), uu2.getClockHiVariant())
  CHECK(uu1.getClockLow(), uu2.getClockLow())
  for i in 10..15:
    if uu1[i] < uu2[i]:
      return -1
    if uu1[i] > uu2[i]:
      return 1
  return 0

# ####################################################################### #
#                              Windows
# ####################################################################### #
when defined(windows):
  import windows

  # Create UUIDs
  proc UuidCreate(Uuid: Tuuid): int 
       {.stdcall, dynlib: "rpcrt4", importc: "UuidCreate".}
  proc UuidCreateSequential(Uuid: Tuuid): int 
       {.stdcall, dynlib: "rpcrt4", importc: "UuidCreateSequential".}
  # String manipulation, use ANSI version
  proc UuidFromStringA(str: cstring, Uuid2: Tuuid): int 
       {.stdcall, dynlib: "rpcrt4", importc: "UuidFromStringA".}
       
  # Make equivalent with libuuid calls
  proc uuid_generate_random*(uuid_out: Tuuid) =
    discard UuidCreate(uuid_out)

  proc uuid_generate_time_safe*(uuid_out: Tuuid): int =
    result = UuidCreateSequential(uuid_out)

  proc uuid_parse*(in_cstr: cstring, uu: Tuuid): int = 
    if cpuEndian == littleEndian:
      # The Windows UuidCreate functions store the first three sections in processor
      # endian order, we need to flip them since UUIDs are Big all the way.
      # see: http://en.wikipedia.org/wiki/Globally_unique_identifier#Binary_encoding
      # Sorry for the hack...
      var out_cstr: cstring
      out_cstr = in_cstr[6] & in_cstr[7] & in_cstr[4] & in_cstr[5] &
                 in_cstr[2] & in_cstr[3] & in_cstr[0] & in_cstr[1] &
                 in_cstr[8] &
                 in_cstr[11] & in_cstr[12] & in_cstr[9] & in_cstr[10] &
                 in_cstr[13] &
                 in_cstr[16] & in_cstr[17] & in_cstr[14] & in_cstr[15] &
                 in_cstr[18] &
                 in_cstr[19] & in_cstr[20] & in_cstr[21] & in_cstr[22] &
                 in_cstr[23] &
                 in_cstr[24] & in_cstr[25] & in_cstr[26] & in_cstr[27] &
                 in_cstr[28] & in_cstr[29] & in_cstr[30] & in_cstr[31] &
                 in_cstr[32] & in_cstr[33] & in_cstr[34] & in_cstr[35]
      result = UuidFromStringA(out_cstr, uu)
    else:
      result = UuidFromStringA(in_cstr, uu)
     
  proc uuid_windows_flip(uu: Tuuid): Tuuid = 
    result = uu
    if cpuEndian == littleEndian:
      # The Windows UuidCreate functions store the first three sections in processor
      # endian order, we need to flip them since UUIDs are Big all the way.
      # see: http://en.wikipedia.org/wiki/Globally_unique_identifier#Binary_encoding
      result.reverse(0, 3)
      result.reverse(4, 5)
      result.reverse(6, 7)

# ####################################################################### #
#                               Linux
# ####################################################################### #
elif defined(linux):
  type Ttimeval {.importc: "struct timeval", header: "<sys/select.h>", final, pure.} = object

  # libuuid.so load pragma
  const libuuid = "libuuid.so.(1|)"

  # clear.c 

  proc uuid_clear*(uu: Tuuid) {.cdecl, importc: "uuid_clear", dynlib: libuuid.}
  # compare.c 
  # Implemented above
  #proc uuid_compare*(uu1: Tuuid; uu2: Tuuid): cint {.cdecl,
  #    importc: "uuid_compare", dynlib: libuuid.}
  # copy.c 

  proc uuid_copy*(dst: Tuuid; src: Tuuid) {.cdecl, importc: "uuid_copy",
      dynlib: libuuid.}
  # gen_uuid.c 

  proc uuid_generate*(uuid_out: Tuuid) {.cdecl, importc: "uuid_generate",
                                     dynlib: libuuid.}
  proc uuid_generate_random*(uuid_out: Tuuid) {.cdecl, 
      importc: "uuid_generate_random", dynlib: libuuid.}
  proc uuid_generate_time*(uuid_out: Tuuid) {.cdecl, importc: "uuid_generate_time",
                                          dynlib: libuuid.}
  proc uuid_generate_time_safe*(uuid_out: Tuuid): cint {.cdecl,
      importc: "uuid_generate_time_safe", dynlib: libuuid.}
  # isnull.c 

  proc uuid_is_null*(uu: Tuuid): cint {.cdecl, importc: "uuid_is_null",
                                         dynlib: libuuid.}
  # parse.c 

  proc uuid_parse*(in_cstr: cstring; uu: Tuuid): cint {.cdecl, importc: "uuid_parse",
      dynlib: libuuid.}
  # unparse.c 

  proc uuid_unparse*(uu: Tuuid; uuid_out: cstring) {.cdecl, importc: "uuid_unparse",
      dynlib: libuuid.}
  proc uuid_unparse_lower*(uu: Tuuid; uuid_out: cstring) {.cdecl,
      importc: "uuid_unparse_lower", dynlib: libuuid.}
  proc uuid_unparse_upper*(uu: Tuuid; uuid_out: cstring) {.cdecl,
      importc: "uuid_unparse_upper", dynlib: libuuid.}
  # uuid_time.c 

  proc uuid_time*(uu: Tuuid; ret_tv: ptr Ttimeval): TTime {.cdecl,
      importc: "uuid_time", dynlib: libuuid.}
  proc uuid_type*(uu: Tuuid): cint {.cdecl, importc: "uuid_type", dynlib: libuuid.}
  proc uuid_variant*(uu: Tuuid): cint {.cdecl, importc: "uuid_variant",
                                         dynlib: libuuid.}
  
# ####################################################################### #
#                              Other OSs
# ####################################################################### #
else:
  raise newException(OsError, "The UUID Library has not been implemented for '" & hostOS & "'")
  

# ####################################################################### #
#                         UUID Create Functions
# ####################################################################### #
proc uuid1*(): Tuuid = 
  var uu: Tuuid
  discard uuid_generate_time_safe(uu)  # TODO: add output check
  when defined(windows):
    uu = uuid_windows_flip(uu)
  result = uu

proc uuid4*(): Tuuid = 
  var uu: Tuuid
  uuid_generate_random(uu)
  when defined(windows):
    uu = uuid_windows_flip(uu)
  result = uu

proc uuidFromStr*(str: string): Tuuid = 
  var cstr = cstring(str)
  discard uuid_parse(cstr, result)  # TODO: add output check


# Tests
when defined(test):
  var rand_uuid, time_uuid: Tuuid
  rand_uuid = uuid4()
  echo "UUID4: " & $rand_uuid
  time_uuid = uuid1()
  echo "UUID1: " & $time_uuid
  #echo strutils.toHex(time_uuid.getTimeLow(), 8)
  #echo strutils.toHex(time_uuid.getTimeMid(), 4)
  #echo strutils.toHex(time_uuid.getTimeHiVersion(), 4)
  #echo strutils.toHex(time_uuid.getClockHiVariant(), 2)
  #echo strutils.toHex(time_uuid.getClockLow(), 2)
  #echo strutils.toHex(time_uuid.getNode(), 12)
  #echo strutils.toHex(time_uuid.getTime(), 15)
  #echo time_uuid.getUnixTime()
  
  assert(time_uuid == time_uuid)
  assert(not (time_uuid == rand_uuid))

  assert(getVersion(time_uuid) == 1)
  assert(getVersion(rand_uuid) == 4)

  var uu1 = uuid1()
  assert(uu1 > time_uuid)

  var uu3 = uuidFromStr($uu1)
  assert(uu1 == uu3)

  echo "SUCCESS: Tests pass!"

when isMainModule:
  var my_uuid = uuid4()
  echo my_uuid
 