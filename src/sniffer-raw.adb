with System;

package body Sniffer.Raw
  with Refined_State => (Network => FD)
is
   package IC renames Interfaces.C;
   use type IC.int;
   use type IC.size_t;

   FD : IC.int := -1;

   procedure Setup
   is
      function C_Socket (Domain   : IC.int;
                         C_Type   : IC.int;
                         Protocol : IC.int) return IC.int
      with
         Global => null,
         Import,
         Convention => C,
         External_Name => "socket";
      PF_INET     : constant IC.int := 2;
      SOCK_RAW    : constant IC.int := 3;
      IPPROTO_UDP : constant IC.int := 17;
   begin
      FD := C_Socket (PF_INET, SOCK_RAW, IPPROTO_UDP);
   end Setup;

   function Valid return Boolean is (FD /= -1) with Refined_Global => (Input => FD);

   procedure Receive (Buffer  : out Buffer_Type;
                      Last    : out Index_Type;
                      Success : out Boolean)
   is
      function C_Recv (FD       : IC.int;
                       Buffer   : Buffer_Type;
                       Length   : IC.size_t;
                       Flags    : IC.int) return IC.int
      with
         Import,
         Convention => C,
         External_Name => "recv",
         global => null,
         Pre  => Length <= IC.size_t (Buffer'Length),
         Post => C_Recv'Result <= IC.int (Buffer'Length);

      procedure C_Perror (Message : String)
        with
          Global => null,
          Import,
          External_Name => "perror";

      Result : IC.int;
   begin
      Buffer := (others => Element_Type'First);
      Result := C_Recv (FD, Buffer, IC.size_t (Buffer'Length), 0);
      if Result > 0 then
         Success := True;
         Last    := Index_Type'Val (Index_Type'Pos (Buffer'First) + IC.int'Pos (Result) - 1);
      else
         Success := False;
         Last := Buffer'First;
         C_Perror ("Error receiving packet len:" & Buffer'Length'Img & ASCII.NUL);
      end if;
   end Receive;

end Sniffer.Raw;
