with System;

package body Raw is

   use type Interfaces.C.int;

   function Setup return Handle
   is
      use Interfaces;
      function C_Socket (Domain   : C.int;
                         C_Type   : C.int;
                         Protocol : C.int) return C.int
      with
         Import,
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
      use Interfaces;
      function C_Recvfrom (FD       : C.int;
                           Buffer   : System.Address;
                           Length   : C.size_t;
                           Flags    : C.int;
                           Unused_1 : C.size_t;
                           Unused_2 : C.size_t) return C.int
      with
         Import,
         External_Name => "recvfrom";
      Result : C.int := C_Recvfrom (H.FD, Buffer'Address, C.size_t (Buffer'Length), 0, 0, 0);
   begin
      if Result >= 0 then
         Success := True;
         Last    := Index_Type'Val (Index_Type'Pos (Buffer'First) + C.int'Pos (Result));
      else
         Success := False;
      end if;
   end Receive;

end Raw;
