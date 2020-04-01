/* packet-enc.c
 *
 * Copyright (c) 2003 Markus Friedl.  All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/aftypes.h>
#include <wsutil/pint.h>
#include <epan/crc16-tvb.h>
#include <epan/crc32-tvb.h>
#include <epan/proto_data.h>
#include <epan/expert.h>

#include "proto.h"





 /* header fields */
static int hf_infocheck_userid = -1;
static int hf_infocheck_hash = -1;
static int hf_infocheck_time = -1;
static int hf_infocheck_ip_sender_system = -1;
static int hf_infocheck_payload = -1;



static dissector_handle_t infocheck_handle;
static int proto_infocheck = -1;
// tree
static gint ett_infocheck = -1;


static int
dissect_infocheck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    
    proto_item *info_ti = proto_tree_add_item(tree, proto_infocheck, tvb, 0, -1, ENC_NA);
    proto_tree *info_tree = proto_item_add_subtree(info_ti, ett_infocheck);
    guint8 offset = 0;
    guint8 lengthfields = 0;
    while (tvb_get_guint16(tvb,offset,ENC_BIG_ENDIAN) != 0x0a20)
    {
        lengthfields++;
        offset++;
    }
    proto_tree_add_item(info_tree, hf_infocheck_userid, tvb, 0, lengthfields, ENC_LITTLE_ENDIAN);
    offset += 2;
    //
    guint8 offset2 = offset;
    lengthfields = 0;
    while (tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN) != 0x0a20)
    {
        lengthfields++;
        offset++;
    }
    proto_tree_add_item(info_tree, hf_infocheck_hash, tvb, offset2, lengthfields, ENC_LITTLE_ENDIAN);
    offset += 2;
    //
    guint8 offset3 = offset;
    lengthfields = 0;
    while (tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN) != 0x0a20)
    {
        lengthfields++;
        offset++;
    }
    proto_tree_add_item(info_tree, hf_infocheck_time, tvb, offset3, lengthfields, ENC_LITTLE_ENDIAN);
    offset += 2;
    //
    guint8 offset4 = offset;
    lengthfields = 0;
    while (tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN) != 0x0a20)
    {
        lengthfields++;
        offset++;
    }
    proto_tree_add_item(info_tree, hf_infocheck_ip_sender_system, tvb, offset4, lengthfields, ENC_LITTLE_ENDIAN);
    offset += 2;
    //
    guint8 offset5 = offset;
    proto_tree_add_item(info_tree, hf_infocheck_payload, tvb, offset5, -1, ENC_LITTLE_ENDIAN);

    return tvb_captured_length(tvb);
}

void
proto_register_infocheck(void)
{
    static hf_register_info hf[] =
    {
       &hf_infocheck_userid,            {"Sender ID"                 ,"infoceck.userid",              FT_STRING,STR_ASCII,NULL,0x0,NULL, HFILL},
       &hf_infocheck_hash,              {"Sender Hash "              ,"infoceck.hash",                FT_BYTES,BASE_NONE,NULL,0x0,NULL, HFILL},
       &hf_infocheck_time,              {"Sending Time"              ,"infoceck.time",                FT_STRING,STR_ASCII,NULL,0x0,NULL, HFILL}, 
       &hf_infocheck_ip_sender_system,  {"Sender IP"                 ,"infoceck.senderIP",            FT_STRING,STR_ASCII,NULL,0x0,NULL, HFILL},
       &hf_infocheck_payload,           {"Sending Payload"           ,"infoceck.payload",             FT_STRING,STR_ASCII,NULL,0x0,NULL, HFILL},
    };

  static gint *ett[] =
  {
      &ett_infocheck,
  };

  proto_infocheck = proto_register_protocol("InfoCheack","InfoCheack", "infocheack");
  register_dissector("infocheack", dissect_infocheck, proto_infocheck); // for dlt_user

  
  proto_register_field_array(proto_infocheck, hf, array_length(hf));//register fields
  proto_register_subtree_array(ett, array_length(ett));// register subtrees

}

void
proto_reg_handoff_infocheack(void)
{
  infocheck_handle  = create_dissector_handle(dissect_infocheck, proto_infocheck);
  dissector_add_for_decode_as("udp.port", infocheck_handle);
  dissector_add_for_decode_as("tcp.port", infocheck_handle);

}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
