## **This document is a user manual for the WebGuard Web Browser Extension for Google Chrome.**

### To install WebGuard:
> Download the source code from this github and extract it to any location of your preference.
> Launch Google Chrome web browser, and import the extension into the browser. 
(You can do this by: extensions > manage extensions > ensure developer mode is on > load unpacked > select the folder of the webguard extension)

Afterwhich, the Webguard extension is now active on your Google Chrome. You can turn the extension on and off via the extension management page of your web browser.

### How do you operate the browser extension?
> No user interaction is required, there are no buttons whatsoever in this extension, simply just have it running and the checks will be automatically performed.
> You will be informed if there are any vulnerabilities on the website via a popup notification box that will show up.
> Should you wish to see the logs generated in the console by WebGuard, proceed to the Manage Extension page for WebGuard and simply click on the service worker hyperlink below it

### Selecting options on the popup notification
When a popup notification boxes show up, you may either click on "ok" or "cancel" option. 
> If you select the "ok" option, you are acknowledging the vulnerabilities, but are not proceeding to allow WebGuard to block/blacklist the website.
> If you select the "cancel" option, the website will be blocked/blacklisted for 1 minute.
(For this project, we have set to 1 minute only for the ease of testing and showcase. This is adjustable should the project is moving towards deployment phase)

Vulnerabiltiies that are detected by the extension include: 
1. SQL Injection vulnerability
2. XSS Vulnerabilities
3. CSRF Vulnerabilities
4. Cancelling download of any suspicious exe files in zip file format.
(For this project, harmless and malicious file hash has been injected into exe files in zip file format hosted on our own web page to simulate user downloading it)
