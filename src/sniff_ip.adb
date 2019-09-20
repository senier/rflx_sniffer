with Sniffer.Types; use Sniffer;
with Sniffer.Raw;
with Sniffer.Dump;
with Sniffer.IPv4.Packet;
use Sniffer.IPv4.Packet;
with Sniffer.In_IPv4.Contains;

procedure Sniff_IP
is
   package Network is new Sniffer.Raw
      (Element_Type => Types.Byte,
       Index_Type   => Types.Index,
       Buffer_Type  => Types.Bytes);
   Last    : Types.Index;
   Success : Boolean;

   subtype Packet is Types.Bytes (1 .. 1500);
   Buffer : Types.Bytes_Ptr := new Packet'(Packet'Range => 0);

   use type Types.Bytes_Ptr; use type Types.Length;

   Ctx : Context := Create;
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
         Initialize (Ctx, Buffer);
         Verify_Message (Ctx);
         if Structural_Valid_Message (Ctx) then
            Sniffer.Dump.IP (Ctx);
            if Present (Ctx, F_Payload) then
               Sniffer.Dump.Payload (Ctx);
            end if;
         end if;
         Take_Buffer (Ctx, Buffer);
      end if;
   end loop;
end Sniff_IP;
