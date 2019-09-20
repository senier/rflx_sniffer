with Ada.Text_IO; use Ada.Text_IO;
with Sniffer.Types;

package body Sniffer.Dump is

   use type Types.Byte;

   function Digit (D : Types.Byte) return Character
   with Pre => D <= 255 - Character'Pos ('a');

   function Digit (D : Types.Byte) return Character
   is
      use type Types.Byte;
   begin
      if D < 10 then
         return Character'Val (Types.Byte'Pos (D) + Character'Pos ('0'));
      else
         return Character'Val (Types.Byte'Pos (D) + Character'Pos ('a') - 10);
      end if;
   end Digit;

   procedure Hex (Buffer : Types.Bytes)
   is
      use type Types.Byte;
      use type Types.Length;
   begin
      Put (" ");
      for E in Buffer'Range
      loop
         if E /= Buffer'First then
            Put (' ');
         end if;
         Put (Digit (Buffer (E) / 16) & Digit (Buffer (E) mod 16));
      end loop;
      New_Line;
   end Hex;

   procedure Payload_Internal (Buffer : Types.Bytes)
   is
   begin
      Put (" Payload:");
      Hex (Buffer);
   end Payload_Internal;

   function Dump_Protocol (Proto : IPv4.Protocol) return String
   with
       Post => Dump_Protocol'Result'Length <= 5;

   function Dump_Protocol (Proto : IPv4.Protocol) return String
   is
   begin
      if Proto.Known
      then
         case Proto.Enum is
            when IPv4.PROTOCOL_UDP => return " UDP";
         end case;
      else
         return Proto.Raw'Img;
      end if;

   end Dump_Protocol;

   use type IPv4.Flag;
   function Dump_Flag (F : IPv4.Flag) return String is
     (if F = IPv4.Flag_True then " 1" else " 0");

   function Dump_Address (Addr : IPv4.Address) return String
   with
      Post => Dump_Address'Result'Length <= 16;

   function Dump_Address (Addr : IPv4.Address) return String
   is
      use type IPv4.Address;
      O1 : constant IPv4.Address := Addr / 256**0 mod 256;
      O2 : constant IPv4.Address := Addr / 256**1 mod 256;
      O3 : constant IPv4.Address := Addr / 256**2 mod 256;
      O4 : constant IPv4.Address := Addr / 256**3 mod 256;

      function I (Octet : IPv4.Address) return String
        with
          Pre => Octet < 256,
          Post => I'Result'Length <= 3;

      function I (Octet : IPv4.Address) return String
      is
         O : constant String := Octet'Img;
         L : constant Natural := (if O'Length <= 4 then O'Length else 4);
      begin
         return O (O'First + 1 .. O'First + L - 1);
      end I;


   begin
      return " " & I (O4) & "." & I (O3) & "." & I (O2) & "." & I (O1);
   end Dump_Address;

   procedure IP (Ctx : IPv4.Packet.Context)
   is
      use Ada.Text_IO;
      use IPv4.Packet;
   begin
      New_Line;
      Put ("IP: Version:" & Get_Version (Ctx)'Img);
      Put (" IHL:" & Get_IHL (Ctx)'Img);
      Put (" DSCP:" & Get_DSCP (Ctx)'Img);
      Put (" ECN:" & Get_ECN (Ctx)'Img);
      Put (" TLen:" & Get_Total_Length (Ctx)'Img);
      Put (" Id:" & Get_Identification (Ctx)'Img);
      Put (" DF:" & Dump_Flag (Get_Flag_DF (Ctx)));
      Put (" MF:" & Dump_Flag (Get_Flag_MF (Ctx)));
      Put (" FOff:" & Get_Fragment_Offset (Ctx)'Img);
      Put (" TTL:" & Get_TTL (Ctx)'Img);
      Put (" Proto:" & Dump_Protocol (Get_Protocol (Ctx)));
      Put (" HCSum:" & Get_Header_Checksum (Ctx)'Img);
      Put (" Src:" & Dump_Address (Get_Source (Ctx)));
      Put (" Dst:" & Dump_Address (Get_Destination (Ctx)));
   end IP;

   procedure UDPD (Ctx : UDP.Datagram.Context)
   is
      use Ada.Text_IO;
      use UDP.Datagram;
   begin
      Put (", UDP:");
      Put (" SPort:" & Get_Source_Port (Ctx)'Img);
      Put (" DPort:" & Get_Destination_Port (Ctx)'Img);
      Put (" Len:" & Get_Length (Ctx)'Img);
      Put (" CSum:" & Get_Checksum (Ctx)'Img);
   end UDPD;


end Sniffer.Dump;
