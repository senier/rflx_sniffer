with Sniffer.IPv4.Packet;
with Sniffer.UDP.Datagram;
with Sniffer.Types;

package Sniffer.Dump is

   use Sniffer;

   procedure Hex (Buffer : Types.Bytes);

   procedure Payload_Internal (Buffer : Types.Bytes);
   procedure Payload is new IPv4.Packet.Get_Payload (Process_Payload => Payload_Internal);
   procedure Payload is new UDP.Datagram.Get_Payload (Process_Payload => Payload_Internal);

   procedure IP (Context : IPv4.Packet.Context_Type)
   with
      Pre => IPv4.Packet.Has_Buffer (Context)
             and then IPv4.Packet.Structural_Valid_Message (Context);

   procedure UDPD (Context : UDP.Datagram.Context_Type)
   with
      Pre => UDP.Datagram.Has_Buffer (Context)
             and then UDP.Datagram.Structural_Valid_Message (Context);

end Sniffer.Dump;
