all: obj/sn_ip obj/sn_ip_in_udp

generated/sniffer-types.ads: specs/ipv4.rflx specs/udp.rflx specs/in_ipv4.rflx
	rflx generate -p sniffer $< generated/

obj/sn_ip obj/sn_ip_in_udp: generated/sniffer-types.ads
	gprbuild -P sniffer.gpr
