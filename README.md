# AppleSchoolManager-Powershell

This repository is a collection of scripts using the Apple Business Manager / Apple School Manager API.

## AXM-API-GetAccessToken.ps1
This script handles the authentication process for the Apple School Manager API.
It creates a signed JWT using your private key, Key ID, and Issuer ID from the Apple Developer portal.
The script then uses this token to make a sample API call to retrieve a list of classes.

It was developed using the sample pythod code at https://developer.apple.com/documentation/apple-school-and-business-manager-api/implementing-oauth-for-the-apple-school-and-business-manager-api, and using Gemini to help convert it to powershell.
