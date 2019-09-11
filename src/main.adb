with Ada.Text_IO; use Ada.Text_IO;
with Types;
with Raw;
with IPv4.Packet;

procedure Main
is
   package Network is new Raw (Element_Type => Types.Byte,
                               Index_Type   => Types.Index_Type,
                               Buffer_Type  => Types.Bytes);
   Handle  : Network.Handle := Network.Setup;
   Last    : Types.Index_Type;
   Success : Boolean;
   Context : IPv4.Packet.Context_Type := IPv4.Packet.Create;

   subtype Packet is Types.Bytes (1 .. 1500);
   Buffer : Types.Bytes_Ptr := new Packet'(others => 0);

begin
   if not Network.Valid (Handle)
   then
      Put_Line ("Error obtaining raw socket");
      return;
   end if;

   loop
      Network.Receive (Handle, Buffer.all, Last, Success);
      if not Success then
         Put_Line ("Error reading packet");
      else
         Put_Line ("Got packet len:" & Last'Img);
         IPv4.Packet.Initialize (Context, Buffer);
         IPv4.Packet.Verify_Message (Context);
         if not IPv4.Packet.Valid_Message (Context) then
            Put_Line ("Message invalid");
         end if;
      end if;
   end loop;
end Main;
