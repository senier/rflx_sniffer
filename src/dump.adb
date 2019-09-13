with Ada.Text_IO;
with Types;

package body Dump is


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

   procedure Hex (Buffer : Types.Bytes)
   is
      use type Types.Byte;
      use type Types.Length_Type;
      use Ada.Text_IO;
   begin
      for E in Buffer'Range
      loop
         if E /= Buffer'First then
            Put (' ');
         end if;
         Put (Digit (Buffer (E) / 16) & Digit (Buffer (E) mod 16));
      end loop;
   end Hex;   
   
   function Dump_Protocol (Proto : IPv4.Protocol_Type) return String is
     (if Proto.Known then " " & Proto.Enum'Img (10 .. Proto.Enum'Img'Last) else Proto.Raw'Img);
     
   use type IPv4.Flag_Type;
   function Dump_Flag (F : IPv4.Flag_Type) return String is
     (if F = IPv4.Flag_True then " 1" else " 0");
      
   function Dump_Address (Addr : IPv4.Address_Type) return String
   is
      use type IPv4.Address_Type;
      O1 : constant IPv4.Address_Type := Addr / 256**0 mod 256;
      O2 : constant IPv4.Address_Type := Addr / 256**1 mod 256;
      O3 : constant IPv4.Address_Type := Addr / 256**2 mod 256;
      O4 : constant IPv4.Address_Type := Addr / 256**3 mod 256;
      function I (O : IPv4.Address_Type) return String is (O'Img (O'Img'First + 1 .. O'Img'Last));
   begin
      return " " & I (O4) & "." & I (O3) & "." & I (O2) & "." & I (O1);
   end Dump_Address;
   
   procedure IP (Context : IPv4.Packet.Context_Type)
   is
      use Ada.Text_IO;
      use IPv4.Packet;
      procedure Dump_Payload is new Get_Payload (Process_Payload => Hex);
   begin
      Put ("Version:" & Get_Version (Context)'Img);
      Put (" IHL:" & Get_IHL (Context)'Img);
      Put (" DSCP:" & Get_DSCP (Context)'Img);
      Put (" ECN:" & Get_ECN (Context)'Img);
      Put (" TLen:" & Get_Total_Length (Context)'Img);
      Put (" Id:" & Get_Identification (Context)'Img);
      Put (" DF:" & Dump_Flag (Get_Flag_DF (Context)));
      Put (" MF:" & Dump_Flag (Get_Flag_MF (Context)));
      Put (" FOff:" & Get_Fragment_Offset (Context)'Img);
      Put (" TTL:" & Get_TTL (Context)'Img);
      Put (" Proto:" & Dump_Protocol (Get_Protocol (Context)));
      Put (" HCSum:" & Get_Header_Checksum (Context)'Img);
      Put (" Src:" & Dump_Address (Get_Source (Context)));
      Put (" Dst:" & Dump_Address (Get_Destination (Context)));
      New_Line;
      Dump_Payload (Context);
      New_Line (2);
   end IP;

end Dump;
