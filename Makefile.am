bin_PROGRAMS       = hflow packet_capture
EXTRA_DIST         = README \
hflowd.schema \
snort.conf pcre.rules \
hflow.spec \
misc/spo_unified.c.patch \
misc/snort-2.4.5-spo_unified.c.patch \
misc/snort-2.6.0-spo_unified.c.patch \
misc/snort-2.6.1.5-spo_unified.c.patch \
misc/sid_map_upload.pl \
misc/gen_map_upload.pl \
misc/makesensor_id.pl \
misc/snort.README \
misc/snort.spec.hflow\
misc/roo1_2_hflow2update.pl\
init.d/hflow
INCLUDES            = @INCLUDES@
sysconf_hflowdir       = $(sysconfdir)/hflow
hflow_SOURCES      = element.h \
active_ipv4_flow_db.hpp  \
frag_drop.hpp \
pcap_ipv4_infile_block.hpp \
ulog_live_ipv4_block.hpp \
bidir_flow_maker_block.hpp \
hflow_sebek_block.hpp  \
pcap_outfile_block.hpp \
flow_db_inserter_block.hpp  \
pcre_flow_tagger_block.hpp \
marker_filter_block.hpp \
l2_helpers.hpp  \
snort_block.hpp \
p0f_block.hpp \
bpf_filter_block.hpp \
pcap_raw_infile_block.hpp \
copy_packet.hpp \
entropy_flow_tagger_block.hpp \
hflow.cpp

sysconf_hflow_DATA  = hflowd.schema snort.conf pcre.rules

packet_capture_SOURCES  = packet_capture.cpp

