with IPv4.Packet;
with Types;

package Dump is

   procedure Hex (Buffer : Types.Bytes);

   procedure IP (Context : IPv4.Packet.Context_Type)
   with
      Pre => IPv4.Packet.Has_Buffer (Context)
             and then IPv4.Packet.Structural_Valid_Message (Context);

end Dump;
