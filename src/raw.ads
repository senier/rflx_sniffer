private with Interfaces.C;

generic
   type Element_Type is private;
   type Index_Type is (<>);
   type Buffer_Type is array (Index_Type range <>) of Element_Type;
package Raw is

   type Handle is private;

   function Setup return Handle;
   function Valid (H : Handle) return Boolean;

   procedure Receive (H       :     Handle;
                      Buffer  : out Buffer_Type;
                      Last    : out Index_Type;
                      Success : out Boolean) with
      Pre  => Valid (H),
      Post => Valid (H);

private
   type Handle is
   record
      FD : Interfaces.C.int;
   end record;
end Raw;
