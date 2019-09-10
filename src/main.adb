with Ada.Text_IO; use Ada.Text_IO;
with Types;
with Raw;

procedure Main
is
   package Network is new Raw (Element_Type => Types.Byte,
                               Index_Type   => Types.Index_Type,
                               Buffer_Type  => Types.Bytes);
   H : Network.Handle := Network.Setup;
   Buf : Types.Bytes (1..1500);
   Len : Types.Index_Type;
   OK  : Boolean;
begin
   if not Network.Valid (H)
   then
      Put_Line ("Error obtaining raw socket");
      return;
   end if;

   loop
      Network.Receive (H, Buf, Len, OK);
      if not OK then
         Put_Line ("Error reading packet");
      else
         Put_Line ("Got packet len:" & Len'Img);
      end if;
   end loop;
end Main;
