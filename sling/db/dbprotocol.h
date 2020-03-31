// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef SLING_DB_DBPROTOCOL_H_
#define SLING_DB_DBPROTOCOL_H_

#include "sling/base/types.h"

namespace sling {

// THE DBSLING protocol is a client-server protocol with a request packet sent
// from a client and the server reponsing with a response packet. Each packet
// consists of a fixed header followed by a verb-specific body.

// Database protocol verbs.
enum DBVerb {
  // Command verbs.
  DBUSE       = 0,     // select database to use
  DBGET       = 1,     // read record(s) from database
  DBPUT       = 2,     // write record(s) to database
  DBDELETE    = 3,     // delete record(s) from database
  DBNEXT      = 4,     // retrieve the next record(s) from database

  // Reply verbs.
  DBOK        = 128,   // success reply
  DBERROR     = 129,   // general error reply
  DBRECORD    = 130,   // reply with record(s)
  DBRESULT    = 131,   // reply with update result(s)
  DBDONE      = 132,   // no more records
};

// Update mode for DBPUT.
enum DBUpdateMode {
  DBOVERWRITE = 0,     // overwrite existing records
  DBADD       = 1,     // only add new records, do not overwrite existing ones
  DBORDERED   = 2,     // do not overwrite records with higher version
};

// Update outcome for DBPUT.
enum DBUpdateOutcome {
  DBNEW       = 0,     // new record added
  DBUPDATED   = 1,     // existing record updated
  DBUNCHANGED = 2,     // record not updated because value is unchanged
  DBEXISTS    = 3,     // record already exists and overwrite not allowed
  DBSTALE     = 4,     // record not updated because version is lower
};

// Database protocol packet header.
struct DBHeader {
  uint32 verb;   // command or reply type
  uint32 size;   // size of packet body

  static DBHeader *from(char *buf) { return reinterpret_cast<DBHeader *>(buf); }
};

// Database protocol exchanges:
//
// DBUSE "dbname" -> DBOK
//
// The DBUSE command selects the database to use for the following commands.
// The request body contains the datanase name and the reply is DBOK if the
// database was selected. Otherwise an error reply is returned.
//
// DBGET {key}* -> DBRECORD {record}*
//
// The request is a list of database keys and the reply is a list of records.
// An empty record value is returned if record is not found.
//
//   key: {
//     ksize:uint32;
//     key: byte[keylen];
//   }
//
//   record: {
//     ksize:uint32;         (lower bit indicates if record version is present)
//     key:byte[ksize >> 1];
//     {version:uint64};     (if ksize & 1)
//     vsize:uint32;
//     value:byte[vsize];
//   }
//
// DBPUT mode:uint32 {record}* -> DBRESULT {outcome:uint32}*
//
// Add/update record(s) in database. The mode controls under which circumstances
// a new record should be written. Returns the outcome for each record.
//
// DBDELETE: {key}* -> DBOK
//
// Delete record(s) from database. Returns DBOK if all records were deleted.
//
// DBNEXT: recid:uint64 num:uint32 -> DBRECORD {record}* next:uint64 | DBDONE
//
// Retrieves the next record(s) for a cursor. The recid is the initial cursor
// value, which should be zero to start retrieving from the begining of the
// datanase, and next is the next cursor value for retrieving more records.
// Returns DBDONE when there are no more records to retrieve.
//
// All requests can return a DBERROR message:char[] reply if an error occurs.

}  // namespace sling

#endif  // SLING_DB_DBPROTOCOL_H_

