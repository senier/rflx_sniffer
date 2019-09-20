with Sniffer.IPv4.Packet;
with Sniffer.UDP.Datagram;
with Sniffer.Types;

package Sniffer.Dump is

   use Sniffer;

   procedure Hex (Buffer : Types.Bytes);

   procedure Payload_Internal (Buffer : Types.Bytes);
   procedure Payload is new IPv4.Packet.Get_Payload (Process_Payload => Payload_Internal);
   procedure Payload is new UDP.Datagram.Get_Payload (Process_Payload => Payload_Internal);

   procedure IP (Ctx : IPv4.Packet.Context)
   with
      Pre => IPv4.Packet.Has_Buffer (Ctx)
             and then IPv4.Packet.Structural_Valid_Message (Ctx);

   procedure UDPD (Ctx : UDP.Datagram.Context)
   with
      Pre => UDP.Datagram.Has_Buffer (Ctx)
             and then UDP.Datagram.Structural_Valid_Message (Ctx);

end Sniffer.Dump;
