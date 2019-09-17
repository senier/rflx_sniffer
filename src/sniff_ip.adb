with Sniffer.Types; use Sniffer.Types;
with Sniffer.Raw;
with Sniffer.Dump;
with Sniffer.IPv4.Packet;
use Sniffer.IPv4.Packet;
with Sniffer.In_IPv4.Contains;
with Sniffer.UDP.Datagram;

procedure Sniff_IP
is
   package Network is new Sniffer.Raw
      (Element_Type => Byte,
       Index_Type   => Index_Type,
       Buffer_Type  => Bytes);
   Last    : Index_Type;
   Success : Boolean;

   subtype Packet is Bytes (1 .. 1500);
   Buffer : Bytes_Ptr := new Packet'(Packet'Range => 0);

   use type Bytes_Ptr; use type Length_Type;

   Context : Context_Type := Create;
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
         Initialize (Context, Buffer);
         Verify_Message (Context);
         if Structural_Valid_Message (Context) then
            Sniffer.Dump.IP (Context);
            if Present (Context, F_Payload) then
               Sniffer.Dump.Payload (Context);
            end if;
         end if;
         Take_Buffer (Context, Buffer);
      end if;
   end loop;
end Sniff_IP;
