# tokenpoacher
Poach SYSTEM tokens for profit!

https://youtu.be/N06auZgg-Kw

Duplicate SYSTEM level tokens using various methods demonstrated in the video
More updates to come soon such as named pipe get SYSTEM techniques

My main goal here was to learn about token management and manipulation, and also find a way to spawn a system shell within the same console without resorting to using a windows service due to CreateProcessAsUser privilege demands.
I found a way around that...stealing tokens from SYSTEM process threads :)  I was getting tired of having to rely so much on CreateProcessWithToken...  It has a "bug" where it always spawns a new command prompt, irregardless of having CREATE_NEW_CONSOLE set or not...and i was determined to learn another way without resorting to named pipes just yet.

This code is HEAVILY under development and not ready for production yet.  It's messy, and all over the place. But it does afford the red teamer some options to work with for easy privilege escalation from admin to SYSTEM
I reiterate, the code is still under development, but wanted to share what i've researched so far

thanks!
