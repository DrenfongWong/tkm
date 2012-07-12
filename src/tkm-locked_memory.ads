generic
   type Element_Type (<>) is private;

package Tkm.Locked_Memory
is

   procedure Lock (Object : access Element_Type);
   --  Lock memory allocated by given object. This prevents that the object's
   --  memory region is paged to the swap area by the kernel. A Locking_Error
   --  exception is raised if paging could not be disabled.

   procedure Wipe (Object : access Element_Type);
   --  Securely wipe memory region allocated by the given object.

   procedure Unlock (Object : access Element_Type);
   --  Unlock memory region allocated by given object. After this call, all
   --  pages that contain a part of the object's memory range can be moved to
   --  external swap space again by the kernel. A Locking_Error exception is
   --  raised if paging could not be enabled.

   Locking_Error : exception;

end Tkm.Locked_Memory;
