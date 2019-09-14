all: obj/sniff_ip obj/sniff_ip_in_udp

generated/sniffer-ipv4.ads generated/sniffer-udp.ads: specs/ipv4.rflx specs/udp.rflx specs/in_ipv4.rflx
	@mkdir -p generated
	rflx generate -p sniffer $^ generated/

obj/sniff_ip: generated/sniffer-ipv4.ads
	gprbuild -P ip_sniffer.gpr

obj/sniff_ip_in_udp: generated/sniffer-udp.ads
	gprbuild -P udp_sniffer.gpr

clean:
	@rm -rf generated obj
