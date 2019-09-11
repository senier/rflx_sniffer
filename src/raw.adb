with Ada.Text_IO; use Ada.Text_IO;
with System;

package body Raw is

   use Interfaces;
   use type Interfaces.C.int;

   function Setup return Handle
   is
      function C_Socket (Domain   : C.int;
                         C_Type   : C.int;
                         Protocol : C.int) return C.int
      with
         Import,
         Convention => C,
         External_Name => "socket";
      PF_INET     : constant C.int := 2;
      SOCK_RAW    : constant C.int := 3;
      IPPROTO_UDP : constant C.int := 17;
   begin
      return Handle'(FD => C_Socket (PF_INET, SOCK_RAW, IPPROTO_UDP));
   end Setup;

   function Valid (H : Handle) return Boolean is (H.FD /= -1);

   procedure Receive (H       :     Handle;
                      Buffer  : out Buffer_Type;
                      Last    : out Index_Type;
                      Success : out Boolean)
   is
      function C_Recv (FD       : C.int;
                       Buffer   : C.char_array;
                       Length   : C.size_t;
                       Flags    : C.int) return C.int
      with
         Import,
         Convention => C,
         External_Name => "recv";

      procedure C_Perror (Message : String) with Import, External_Name => "perror";

      C_Buffer : C.char_array (1 .. Buffer'Length) with Address => Buffer'Address;
      Result : C.int := C_Recv (H.FD, C_Buffer, C.size_t (Buffer'Length), 0);
   begin
      if Result >= 0 then
         Success := True;
         Last    := Index_Type'Val (Index_Type'Pos (Buffer'First) + C.int'Pos (Result));
      else
         Success := False;
         C_Perror ("Error receiving packet len:" & Buffer'Length'Img & ASCII.NUL);
      end if;

      Put_Line ("Result:" & Result'Img);
   end Receive;

end Raw;
