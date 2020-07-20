# Yara rules file

The included yara rules file verification.yar can be used to verify whether or not the memory is detected either with Volatility/Rekall's yarascan or with the Yara executable itself.

This applies mostly to scenarios where shellcode is used. The shellcode typically contains an appended string token:

    AAAAAAAAAAAAAAAAAA_what.the.eyes.see.and.the.ears.hear..the.mind.believes_AAAAAAAAAAAAAAAAAA

