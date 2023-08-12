
![the-shining-tricycle](https://github.com/g3tsyst3m/tokenpoacher/assets/19558280/6a74eba4-7a60-4e13-8c5f-d592e4de8858)


# Elevation Station
Stealing and Duplicating SYSTEM tokens for fun & profit!  We duplicate things, make twin copies, and then ride away.

You have used Metasploit's getsystem and SysInternals PSEXEC for getting system privs, correct?  Well, here's a similar standalone version of that...but without the AV issues...at least for now 😸  

This tool also enables you to become **TrustedInstaller**, similar to what Process Hacker/System Informer can do.  This functionality is very new and added in the latest code release and binary release as of 8/12/2023!

💵💲If you like this tool and would like to help support me in my efforts improving this solution and others like it, please feel free to hit me up on Patreon!
https://patreon.com/G3tSyst3m

<b>quick rundown on commands</b>

<b>Bypass UAC and escalate from medium integrity to high (must be member of local admin group)

![uacbyp](https://github.com/g3tsyst3m/elevationstation/assets/19558280/c0dd63c9-635a-4c83-983b-ef37c27d1106)

<b> Become Trusted Installer!

![trustedinstaller](https://github.com/g3tsyst3m/elevationstation/assets/19558280/7560e785-d4b6-4914-96e5-1b0e7f922e7f)

<b>Duplicate Process Escalation Method

![dupprocess](https://github.com/g3tsyst3m/elevationstation/assets/19558280/06b17b2f-046b-4376-b6ae-09a9e31f3821)

Duplicate Thread Escalation Method

![dupthread](https://github.com/g3tsyst3m/elevationstation/assets/19558280/62a2763c-c356-4f77-961b-4d8ecd671b93)

Named Pipes Escalation method

![namedpipes2](https://github.com/g3tsyst3m/elevationstation/assets/19558280/b75e5455-ad5f-4aa3-9b64-31fcc22501f1)

Create Remote Thread injection method
![CreateRemoteThread](https://github.com/g3tsyst3m/elevationstation/assets/19558280/a4b67302-3b26-4f48-ad37-4473dd87d37a)

</b>

## What it does

ElevationStation is a privilege escalation tool.  It works by borrowing from commonly used escalation techniques involving manipulating/duplicating process and thread tokens.  

## Why reinvent the wheel with yet another privilege escalation utility?

This was a combined effort between avoiding AV alerts using Metasploit and furthering my research into privilege escalation methods using tokens.  In brief: My main goal here was to learn about token management and manipulation, and to effectively bypass AV.  I knew there were other tools out there to achieve privilege escalation using token manip but I wanted to learn for myself how it all works.

## So...How does it work?

Looking through the terribly organized code, you'll see I used two **primary** methods to get SYSTEM so far; stealing a Primary token from a SYSTEM level process, and stealing an Impersonation thread token to convert to a primary token from another SYSTEM level process.  That's the general approach at least.

## CreateProcessAsUser versus CreateProcessWithToken

This was another driving force behind furthering my research.  Unless one resorts to using named pipes for escalation, or inject a dll into a system level process, I couldn't see an easy way to spawn a SYSTEM shell within the same console AND meet token privilege requirements.

<b> Let me explain... </b>

When using CreateProcessWithToken, it ALWAYS spawns a separate cmd shell.  As best that I can tell, this "bug" is unavoidable.  It is unfortunate, because CreateProcessWithToken doesn't demand much as far as token privileges are concerned.  Yet, if you want a shell with this Windows API you're going to have to resort to dealing with a new SYSTEM shell in a separate window

That leads us to CreateProcessAsUser. I knew this would spawn a shell within the current shell, but I needed to find a way to achieve this without resorting to using a windows service to meet the token privilege requirements, namely: 
- SE_ASSIGNPRIMARYTOKEN_NAME
TEXT("SeAssignPrimaryTokenPrivilege")
- SE_INCREASE_QUOTA_NAME
TEXT("SeIncreaseQuotaPrivilege")

I found a way around that...stealing tokens from SYSTEM process threads :)  We duplicate the thread IMPERSONATION token, set the thread token, and then convert it to primary and then re-run our enable privileges function.  This time, the enabling of the two privileges above succeeds and we are presented with a shell within the same console using CreateProcessAsUser.  No dll injections, no named pipe impersonations, just token manipulation/duplication. 

## Progress

This has come a long way so far...and I'll keep adding to it and cleaning up the code as time permits me to do so. Thanks for all the support and testing!
