
#define EXTRACT_LE_16BITS(p) \
  ((u_int16_t)((u_int16_t)*((const u_int8_t *)(p) + 1) << 8 | \
	       (u_int16_t)*((const u_int8_t *)(p) + 0)))

#define pletohs(p)  ((u_int16_t)                       \
  ((u_int16_t)*((const u_int8_t *)(p)+1)<<8|  \
   (u_int16_t)*((const u_int8_t *)(p)+0)<<0))

#define pletohl(p)  ((u_int32_t)*((const u_int8_t *)(p)+3)<<24|  \
  (u_int32_t)*((const u_int8_t *)(p)+2)<<16|  \
  (u_int32_t)*((const u_int8_t *)(p)+1)<<8|   \
		     (u_int32_t)*((const u_int8_t *)(p)+0)<<0)



#define pletoh64(p) ((u_int64_t)*((const u_int8_t *)(p)+7)<<56|  \
  (u_int64_t)*((const u_int8_t *)(p)+6)<<48|  \
  (u_int64_t)*((const u_int8_t *)(p)+5)<<40|  \
  (u_int64_t)*((const u_int8_t *)(p)+4)<<32|  \
  (u_int64_t)*((const u_int8_t *)(p)+3)<<24|  \
  (u_int64_t)*((const u_int8_t *)(p)+2)<<16|  \
  (u_int64_t)*((const u_int8_t *)(p)+1)<<8|   \
		     (u_int64_t)*((const u_int8_t *)(p)+0)<<0)


#define DATA_FRAME_IS_QOS(x)            ((x) & 0x08)
#define FC_TO_DS(fc)            ((fc) & 0x0100)
#define FC_FROM_DS(fc)          ((fc) & 0x0200)
#define FC_MORE_FLAG(fc)        ((fc) & 0x0400)
#define FC_RETRY(fc)            ((fc) & 0x0800)
#define FC_POWER_MGMT(fc)       ((fc) & 0x1000)
#define FC_MORE_DATA(fc)        ((fc) & 0x2000)
#define FC_WEP(fc)              ((fc) & 0x4000)
#define FC_ORDER(fc)            ((fc) & 0x8000)
#define FC_TYPE(fc)             (((fc) >> 2) & 0x3)
#define FC_SUBTYPE(fc)          (((fc) >> 4) & 0xF)

#define BIT(x) (1 << (x))

#define IEEE80211_FTYPE_DATA    0x0008
#include <sys/types.h>
typedef u_int8_t u8;
typedef u_int16_t u16;

struct udp_hdr {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */
	u_short	uh_sum;			/* datagram checksum */
};

/*
 * A somewhat abstracted view of the LLC header
 */

struct llc_hdr {
  u_int8_t dsap;
  u_int8_t ssap;
  struct {
    u_int8_t ui;
    u_int8_t org_code[3];
    u_int16_t ether_type;
  } snap;
};

struct ieee80211_hdr {
    u16 frame_control;
    u16 duration_id;
    u8 addr1[6];
    u8 addr2[6];
    u8 addr3[6];
    u16 seq_ctrl;
    u8 addr4[6];
} __attribute__ ((packed));

struct tcp_hdr {
  u16 sport;               /* source port */
  u16 dport;               /* destination port */
  u_int32_t seq;                 /* sequence number */
  u_int32_t ack;                 /* acknowledgement number */
  u8  offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
  u8  flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u16 win;                 /* window */
  u16 sum;                 /* checksum */
  u16 urp;                 /* urgent pointer */
};

struct ssl_hdr {
  u8 ssl_content_type;
  u16 version;
  u16 length;
}__attribute__ ((packed));
