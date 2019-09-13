with Ada.Text_IO; use Ada.Text_IO;
with Types;
with Raw;
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

   function Digit (D : Types.Byte) return Character
   is
      use type Types.Byte;
   begin
      if D < 10 then
         return Character'Val (Types.Byte'Pos (D) + 48);
      else
         return Character'Val (Types.Byte'Pos (D) + 87);
      end if;
   end Digit;

   procedure Dump (Buffer : Types.Bytes)
   is
      use type Types.Byte;
   begin
      for E in Buffer'Range
      loop
         if E /= Buffer'First then
            Put (' ');
         end if;
         Put (Digit (Buffer (E) / 16) & Digit (Buffer (E) mod 16));
      end loop;
   end Dump;

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
      if not Success then
         Put_Line ("Error reading packet");
      else
         Put_Line ("Got packet len:" & Last'Img);
         Dump (Buffer (Buffer'First .. Last));
         IPv4.Packet.Initialize (Context, Buffer);
         IPv4.Packet.Verify_Message (Context);

         for F in IPv4.Packet.F_Version .. IPv4.Packet.F_Payload loop
            if not IPv4.Packet.Valid (Context, F) then
               Put_Line ("Invalid " & F'Img);
            end if;
         end loop;

         if not IPv4.Packet.Valid_Message (Context) then
            Put_Line ("Message invalid");
         end if;
         IPv4.Packet.Take_Buffer (Context, Buffer, Unused_Bit_Index);
      end if;
   end loop;
end Main;
