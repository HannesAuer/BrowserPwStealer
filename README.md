# <img src="https://user-images.githubusercontent.com/62036141/227040593-70997ac6-f6a8-4d9f-97dc-1a24e9c6c28a.png" width="25" height="25"/> BrowserPwStealer
C# class to get all browser passwords

## Description
This is a C# class that provides methods to get a list of all **browser passwords** including their **username** and **URL**. <br>
Following browser are included:
- Google Chrome
- Brave
- Opera
- Microsoft Edge
- Firefox

## Getting Started
### Prerequisites
- A C# project to which you want to add this class.

### Installation
- Download BrowserPwStealer.cs to your project folder.
- Or copy all code from BrowserPwStealer.cs to your project.

Now you can call all methods with **BrowserPwStealer.\[METHOD\](\[PARAMS\]\)**.

## How to use BrowserPwStealer.cs?
_Call the methods in your project with **BrowserPwStealer.\[METHOD\]\(\[PARAMS\]\)**_

### Following Methods are available:
**Chromium Browsers**
- GetChromeLoginData(bool killProcess)
- GetBraveLoginData(bool killProcess)
- GetOperaLoginData(bool killProcess)
- GetMsEdgeLoginData(bool killProcess)
- GetChromiumBrowserLoginData(string processName, string loginDataPath, string localStatePath, bool killProcess)

**Firefox Browser**
- GetFirefoxLoginData(bool killProcess)
- GetFirefoxBrowserLoginData(string processName, string profilePath, string mozillaPath, bool killProcess)

## Method examples:
### GetChromeLoginData:
- `killProcess`: Kill browser process. Maybe needed while grabbing Data.
```
string output = BrowserPwStealer.GetChromeLoginData(false);
Console.WriteLine(output);
```
Output:
> ++++++++++ C:\Users\USER\AppData\Local\Google\Chrome\User Data\Default ++++++++++
>
> URL: hxxps://some-website.xyz<br>
> USERNAME: TestUser01<br>
> PASSWORD: SecretPassword

### GetChromiumBrowserLoginData:
- `processName`: Processname of brower to kill it if its opened. "-" to not kill any browser.
- `loginDataPath`: Full path to login data file.
- `localStatePath`: Full path to local state file.
- `killProcess`: Kill browser process. Maybe needed while grabbing Data.
```
string output = BrowserPwStealer.GetChromiumBrowserLoginData("PROCESSNAME", "CUSTOME LOGIN DATA PATH", "CUSTOME LOCAL STATE PATH", false);
Console.WriteLine(output);
```
Output:
> ++++++++++ CUSTOM PATH ++++++++++
>
> URL: hxxps://some-website.xyz<br>
> USERNAME: TestUser01<br>
> PASSWORD: SecretPassword

### GetFirefoxBrowserLoginData:
- `processName`: Processname of brower to kill it if its opened. "-" to not kill any browser.
- `profilePath`: Full path to profile.
- `mozillaPath`: Full path to mozilla program.
- `killProcess`: Kill browser process. Maybe needed while grabbing Data.
```
string output = BrowserPwStealer.GetFirefoxBrowserLoginData("PROCESSNAME", "CUSTOME PROFILE PATH", "CUSTOME MOZILLA PATH", false);
Console.WriteLine(output);
```
Output:
> ++++++++++ CUSTOM PATH ++++++++++
>
> URL: hxxps://some-website.xyz<br>
> USERNAME: TestUser01<br>
> PASSWORD: SecretPassword

## Licence
This project is licensed under the MIT License - see the [LICENSE.md](LICENSE) file for details.
