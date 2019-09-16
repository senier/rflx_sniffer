with Sniffer.Types;
with Sniffer.Raw;
with Sniffer.Dump;
with Sniffer.IPv4.Packet;
with Sniffer.In_IPv4.Contains;
with Sniffer.UDP.Datagram;

procedure Sniff_IP
is
   use Sniffer;
   package Network is new Raw (Element_Type => Types.Byte,
                               Index_Type   => Types.Index_Type,
                               Buffer_Type  => Types.Bytes);
   Last    : Types.Index_Type;
   Success : Boolean;

   subtype Packet is Types.Bytes (1 .. 1500);
   Buffer : Types.Bytes_Ptr := new Packet'(Packet'Range => 0);

   use type Types.Bytes_Ptr;
   use type Types.Length_Type;

   Context : IPv4.Packet.Context_Type := IPv4.Packet.Create;
begin
   Network.Setup;
   if not Network.Valid
   then
      return;
   end if;

   loop
      pragma Loop_Invariant (Buffer /= null and then Buffer'Last = Packet'Last);
      Network.Receive (Buffer.all, Last, Success);
      if Success then
         IPv4.Packet.Initialize (Context, Buffer);
         IPv4.Packet.Verify_Message (Context);
         if IPv4.Packet.Structural_Valid_Message (Context) then
            Dump.IP (Context);
            if IPv4.Packet.Present (Context, IPv4.Packet.F_Payload) then
               Dump.Payload (Context);
            end if;
         end if;
         IPv4.Packet.Take_Buffer (Context, Buffer);
      end if;
   end loop;
end Sniff_IP;
