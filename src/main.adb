with Ada.Text_IO; use Ada.Text_IO;
with Types;
with Raw;
with Dump;
with IPv4.Packet;

procedure Main
is
   package Network is new Raw (Element_Type => Types.Byte,
                               Index_Type   => Types.Index_Type,
                               Buffer_Type  => Types.Bytes);
   Last    : Types.Index_Type;
   Success : Boolean;
   Context : IPv4.Packet.Context_Type := IPv4.Packet.Create;

   subtype Packet is Types.Bytes (1 .. 1500);
   C : constant Packet := (others => 0);
   Buffer : Types.Bytes_Ptr := new Packet'(C);
   Unused_Bit_Index : Types.Bit_Length_Type;
   use type Types.Bytes_Ptr;
   use type Types.Length_Type;

begin
   Network.Setup;
   if not Network.Valid
   then
      Put_Line ("Error obtaining raw socket");
      return;
   end if;

   loop
      pragma Loop_Invariant (Buffer /= null);
      pragma Loop_Invariant (Buffer'Last = 1500);

      Network.Receive (Buffer.all, Last, Success);
      if Success then
         IPv4.Packet.Initialize (Context, Buffer);
         IPv4.Packet.Verify_Message (Context);

         if IPv4.Packet.Structural_Valid_Message (Context) then
            Dump.IP (Context);
         end if;
         IPv4.Packet.Take_Buffer (Context, Buffer, Unused_Bit_Index);
      end if;
   end loop;
end Main;
