# TokenPoacher
Poach SYSTEM tokens for fun & profit!

https://youtu.be/N06auZgg-Kw - quick rundown on commands

https://youtu.be/BwWOXgqANZU - I walk/talk you through how to use this tool and what it does.  We will review some of the code, explain how to use Process Hacker/System Informer to review token privileges and assigned privileges via the tool, and more! 

## What it does

Token Poacher is a privilege escalation tool.  It works by borrowing from commonly used escalation techniques involving duplication of process and thread tokens.  The current version supports escalating from local admin to SYSTEM by duplicating the primary token from a SYSTEM process and duplicating the impersonation thread token from a SYSTEM process. 

## Why reinvent the wheel with yet another privilege escalation utility?

This was a combined effort between avoiding AV alerts using Metasploit and furthering my research into privilege escalation methods.  In brief: My main goal here was to learn about token management and manipulation, and to effectively bypass AV.  I knew there were other tools out there to achieve privilege escalation using token manip but I wanted to learn for myself how it all works.

## So...How does it work?

Looking through the terribly organized code, you'll see I used two methods to get SYSTEM so far; stealing a Primary token from a SYSTEM level process, and stealing an Impersonation thread token to convert to a primary token from another SYSTEM level process.  

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

## What are the "Experimental" features?

Glad you asked :)  There are occasions where the red teamer needs to lower their process integrity levels.  This does just that...however, it's not as I'd like it to be just yet.  I probably need to resort to creating a restricted token when lowering the process integrity, say from SYSTEM to HIGH, or HIGH to MEDIUM.  If you're running in an elevated process, it keeps the elevated token but reduces the integrity.  So, that's a current "bug" I'm working through.

Another experimental feature is executing various API functions using SYSTEM impersonation tokens.  One could write a file to disk in another user's folder, create a new user and add them to the administrators group, etc. An example of this where we use the impersonation token to create a file under another user's directory is included in the code, but I currently have it commented out.

## Progress

This code is HEAVILY under development and not ready for production yet.  It's messy, and all over the place. But it does afford the red teamer some options to work with for easy privilege escalation from admin to SYSTEM
I was just eager to share what i've researched so far.  

Thanks!

More updates to come soon such as integrating named pipe get SYSTEM techniques
