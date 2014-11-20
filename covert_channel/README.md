covert_channel


This project is about doing message transfer using intentionally
corrupted frames in the wireless channel. The repo currently has the
userland code for creating a covert channel in wireless broadcast
medium.



While trying to run the code:
Check the values for the DLT_EEE802_11_RADIO headers given by your
network adapter - this is hardcoded in the prototype.

Check that you assign the correct TUN interface name and give the
right options for the receiver and the sender.

Check the shell scripts on which names you should provide.

The MAC addresses are used as tag, in the prototype to *identify*
denali frames, make sure you comment related changes if you want to
exchange messages using Denali.

You can chose to ignore the key exchange step and already have your
shared key between parties already, otherwise share a pair of keys
for the first step and keep them in the keys folder for software to
read them.

Note, the patch is for a specific version of compat-wireless tarball
attached, which should be used for generating corrupted packets.

Update: Patched with the last commit - encrypting the message length,
instead of transmitting in the clear.
