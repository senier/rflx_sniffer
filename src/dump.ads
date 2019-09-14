with IPv4.Packet;
with UDP.Datagram;
with Types;

package Dump is

   procedure Hex (Buffer : Types.Bytes);
   procedure Payload (Buffer : Types.Bytes);

   procedure IP (Context : IPv4.Packet.Context_Type)
   with
      Pre => IPv4.Packet.Has_Buffer (Context)
             and then IPv4.Packet.Structural_Valid_Message (Context);

   procedure UDPD (Context : UDP.Datagram.Context_Type)
   with
      Pre => UDP.Datagram.Has_Buffer (Context)
             and then UDP.Datagram.Structural_Valid_Message (Context);

end Dump;
