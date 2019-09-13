with IPv4.Packet;

package Dump is

   procedure IP (Context : IPv4.Packet.Context_Type)
   with
      Pre => IPv4.Packet.Structural_Valid_Message (Context);

end Dump;
