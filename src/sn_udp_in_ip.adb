with Ada.Text_IO; use Ada.Text_IO;
with Types;
with Raw;
with Dump;
with IPv4.Packet;
with In_IPv4.Contains;
with UDP.Datagram;

procedure Sn_UDP_in_IP
is
   use type Types.Bytes_Ptr;
   use type Types.Length_Type;

   package Network is new Raw (Element_Type => Types.Byte,
                               Index_Type   => Types.Index_Type,
                               Buffer_Type  => Types.Bytes);
   Last    : Types.Index_Type;
   Success : Boolean;
   IP_Context  : IPv4.Packet.Context_Type := IPv4.Packet.Create;
   UDP_Context : UDP.Datagram.Context_Type := UDP.Datagram.Create;

   pragma Unevaluated_Use_Of_Old (Allow);

   procedure Take_Buffer (IP_Context  : in out IPv4.Packet.Context_Type;
                          UDP_Context : in out UDP.Datagram.Context_Type;
                          Buffer      :    out Types.Bytes_Ptr)
   with
      Pre  => IPv4.Packet.Has_Buffer (IP_Context)
              or UDP.Datagram.Has_Buffer (UDP_Context),
      Post => Buffer /= null
              and then (if IPv4.Packet.Has_Buffer (IP_Context)'Old
                        then IP_Context.Buffer_Last'Old = Buffer'Last
                        elsif UDP.Datagram.Has_Buffer (UDP_Context)'Old
                        then UDP_Context.Buffer_Last'Old = Buffer'Last
                        else False);


   procedure Take_Buffer (IP_Context  : in out IPv4.Packet.Context_Type;
                          UDP_Context : in out UDP.Datagram.Context_Type;
                          Buffer      :    out Types.Bytes_Ptr)
   is
      Unused_Bit_Index : Types.Bit_Index_Type;
   begin
      if IPv4.Packet.Has_Buffer (IP_Context) then
         IPv4.Packet.Take_Buffer (IP_Context, Buffer, Unused_Bit_Index);
      elsif UDP.Datagram.Has_Buffer (UDP_Context) then
         UDP.Datagram.Take_Buffer (UDP_Context, Buffer, Unused_Bit_Index);
      else
         pragma Assert (False);
      end if;
   end Take_Buffer;

   subtype Packet is Types.Bytes (1 .. 1500);
   C : constant Packet := (others => 0);
   Buffer : Types.Bytes_Ptr := new Packet'(C);

   procedure Dump_Payload is new IPv4.Packet.Get_Payload (Process_Payload => Dump.Hex);
   procedure Dump_Payload is new UDP.Datagram.Get_Payload (Process_Payload => Dump.Hex);

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
         IPv4.Packet.Initialize (IP_Context, Buffer);
         IPv4.Packet.Verify_Message (IP_Context);

         if IPv4.Packet.Structural_Valid_Message (IP_Context) then
            Dump.IP (IP_Context);
            if In_IPv4.Contains.UDP_Datagram_In_IPv4_Packet_Payload (IP_Context)
            then
               In_IPv4.Contains.Switch (IP_Context, UDP_Context);
               UDP.Datagram.Verify_Message (UDP_Context);
               if UDP.Datagram.Structural_Valid_Message (UDP_Context)
               then
                  Dump.UDPD (UDP_Context);
                  if UDP.Datagram.Present (UDP_Context, UDP.Datagram.F_Payload)
                  then
                     Dump_Payload (UDP_Context);
                  end if;
               end if;
            elsif IPv4.Packet.Present (IP_Context, IPv4.Packet.F_Payload)
            then
               Dump_Payload (IP_Context);
            end if;
            New_Line;
         end if;

         Take_Buffer (IP_Context, UDP_Context, Buffer);
         pragma Assert (Buffer'Last = 1500);
      end if;
   end loop;
end Sn_UDP_in_IP;
